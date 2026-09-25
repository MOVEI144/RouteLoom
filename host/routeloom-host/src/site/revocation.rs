//! RRS1 distribution (04-removal-revocation.md §9, plan P6-1 PR A).
//!
//! `membership.revoke` commits first (ledger + RRS1 + staged GK, one
//! transaction) and only then distributes: every revoke snapshots its
//! surviving members as distribution targets, and the tick-driven
//! distributor pushes the latest RRS1 over the authority channel until
//! each target proves it applied the set — or stays honestly `unknown`.
//! Nothing is ever counted as a success without an Applied ACK.
//!
//! The transport is a port ([`RevocationTransport`]): production
//! attaches the channel port ([`super::p6_channel::P6ChannelTransport`],
//! `capabilities.get` then reports `rrs_ready`), no port means
//! `rrs_no_transport`, and tests inject in-process fakes. The
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

use super::authority_channel::{AuthorityOutbound, ChannelEvent, ChannelMember};
use super::p6_channel::P6Receipt;
use super::records::{h16, parse_h16, parse_hex};
use super::store::{Batch, DocKind};
use super::{SiteAuthority, SiteError};
use crate::receive_log::hex_lower;
use routeloom_protocol::authority::CarrierKind;

/// Targets snapshotted per operation (the P6 profile: ~100 deployed
/// boards plus headroom, gateway included). Members beyond the cap are
/// counted as `overflow` (honestly `unknown`, never silently dropped).
pub const DISTRIBUTION_TARGET_MAX: usize = 128;
/// Shared mail outbox (RRS1 now; GrantRenew joins it in PR C).
pub const DISTRIBUTION_OUTBOX_MAX: usize = 4;
/// At most 10 object sends per second, authority-wide.
pub const DISTRIBUTION_DISPATCH_GAP_MS: u64 = 100;
/// Backoff schedule (seconds): targets advance through 5/10/20/40/60 s
/// and keep retrying at the capped 60 s level;
/// transport refusals back off each queued mail to the same cap.
pub const DISTRIBUTION_BACKOFF_S: [u64; 5] = [5, 10, 20, 40, 60];
/// Adds one, refusing to wrap: the generation/rs_epoch/gk_epoch counters
/// stop at u32::MAX with an explicit error instead of aliasing an older
/// credential. Checked before the revoke transaction.
pub fn checked_next(value: u32, what: &str) -> Result<u32, SiteError> {
    value.checked_add(1).ok_or_else(|| {
        SiteError::new(
            "COUNTER_EXHAUSTED",
            format!("{what} counter exhausted; safe maintenance is required"),
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

/// The P5 authority channel's send half (PR A: port only). Returns
/// false when the object was not sent (backpressure / no route); the
/// distributor retries with backoff and never treats a refusal as an ACK.
///
/// The port carries plaintext authority payloads — the RRS1 object
/// (type 5), the RemovalNotice (type 6), the GrantRenew PREPARE/COMMIT
/// (type 7) — and the future P5 channel seals them into the addressed
/// network's context at send time. The `network` on `send_notice` and
/// `send_grant` selects the required context; an old-network notice must
/// never be sealed under a new-network context.
pub trait RevocationTransport {
    fn send_rrs(&mut self, node: u64, object: &[u8]) -> bool;
    /// Sends a type-6 RemovalNotice. Default refuses until wired.
    fn send_notice(&mut self, _node: u64, _network: u64, _notice: &[u8]) -> bool {
        false
    }
    /// Captures one exact type-6 ciphertext before a revoke commit.
    /// A production channel never sends it from this call.
    fn preseal_notice(&mut self, _node: u64, _network: u64, _notice: &[u8]) -> Option<Vec<u8>> {
        None
    }
    /// Sends the durable, already-sealed ciphertext after commit, including
    /// after a host restart that lost the RAM authority channel.
    fn send_presealed_notice(&mut self, _node: u64, _sealed: &[u8]) -> bool {
        false
    }
    /// Sends a type-7 GrantRenew plaintext over `network`'s authority
    /// context. Default refuses until wired.
    fn send_grant(&mut self, _node: u64, _network: u64, _plaintext: &[u8]) -> bool {
        false
    }
    /// True when `send_notice` can deliver. The distributor only queues
    /// supported kinds, so an RRS-only port never wedges behind
    /// notices it cannot carry (the outbox dispatches head-first).
    fn carries_notice(&self) -> bool {
        false
    }
    /// True when `send_grant` can deliver (same head-of-line rule).
    fn carries_grant(&self) -> bool {
        false
    }
    /// True for the production channel port (P6 PR D). Fakes stay
    /// false so `capabilities.get` keeps reporting `rrs_no_transport`
    /// until a real port is attached.
    fn p6_ready(&self) -> bool {
        false
    }
    /// The USB/mesh egress is currently bound. A detached production
    /// port retains mail without counting a send attempt.
    fn set_delivery_attached(&mut self, _attached: bool) {}
    /// Feeds one inbound carrier into the port (reassembled USB 0x64 /
    /// mesh envelope, R1 or R3). Default ignores: fakes deliver
    /// reports by calling the handlers directly.
    fn push_carrier(&mut self, _device: u64, _kind: CarrierKind, _bytes: &[u8], _now_ms: u64) {}
    /// Takes the verified P6 reports queued since the last call.
    fn poll_p6_receipts(&mut self) -> Vec<P6Receipt> {
        Vec::new()
    }
    /// Other events from the shared P5/P6 channel table.
    fn poll_channel_events(&mut self) -> Vec<ChannelEvent> {
        Vec::new()
    }
    /// Takes every queued outbound carrier for the USB/mesh mapping.
    fn take_p6_carriers(&mut self) -> Vec<AuthorityOutbound> {
        Vec::new()
    }
    /// Syncs the live member bindings (called every authority tick).
    /// `mono_ms` drives retention expiry and the cutover grace.
    fn refresh_p6_bindings(
        &mut self,
        _live: &[(u64, ChannelMember)],
        _current_network: u64,
        _rs_epoch: u32,
        _gk_epoch: u32,
        _mono_ms: u64,
    ) {
    }
    /// Notes a cutover commit so the port can serve the old network's
    /// COMMIT grace before flipping to the new network.
    fn note_p6_cutover(&mut self, _old_network: u64, _mono_ms: u64) {}
    /// Notes a Get answer for the per-device spam gap. False drops
    /// the answer (answered too recently).
    fn note_p6_get_answer(&mut self, _device: u64, _mono_ms: u64) -> bool {
        true
    }
    /// True when a notice to `node` on `network` could still seal.
    /// When false the distributor marks the notice `unreachable`
    /// instead of retrying forever.
    fn notice_sealable(&self, _node: u64, _network: u64, _mono_ms: u64) -> bool {
        true
    }
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

/// What one queued mail carries. The outbox is shared (04 §9.1: at
/// most 4 live mails across RRS1, notices and grants); notices queue
/// ahead of grants, grants ahead of RRS1 fan-out.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OutboundKind {
    Rrs,
    Notice,
    Prepare,
    Commit,
}

/// One queued object send (RAM-only; rebuilt from the snapshot).
pub struct OutboundRrs {
    pub op: u64,
    pub node: u64,
    pub what: OutboundKind,
}

/// RemovalNotice delivery (04 §7.1, `revoke` only). The signed 103 B
/// object commits with the revoke; the tick sends it after commit —
/// never before — and the type-5 sub-3 accept receipt confirms the
/// durable intent (not the erase: no remote erase proof exists).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoticeState {
    pub object: Vec<u8>,
    /// Exact encrypted type-6 carrier captured before the revoke commit.
    /// Replays use these bytes; a restart does not reseal with a new key.
    pub sealed: Option<Vec<u8>>,
    /// The AAD network the notice was issued for.
    pub network: u64,
    pub delivery: NoticeDelivery,
    pub intent_confirmed: bool,
    /// Best-effort resends stop after this many transport sends.
    pub attempts: u32,
}

/// `pending` (committed, never sent), `sent` (the transport took it at
/// least once), or `unreachable` (no authority context existed at
/// removal — a DAMS was never delivered — so nothing can seal it).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoticeDelivery {
    Pending,
    Sent,
    Unreachable,
}

/// Best-effort notice resends (04 §7.1).
pub const NOTICE_SEND_MAX: u32 = 3;

impl NoticeDelivery {
    fn name(self) -> &'static str {
        match self {
            NoticeDelivery::Pending => "pending",
            NoticeDelivery::Sent => "sent",
            NoticeDelivery::Unreachable => "unreachable",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(NoticeDelivery::Pending),
            "sent" => Some(NoticeDelivery::Sent),
            "unreachable" => Some(NoticeDelivery::Unreachable),
            _ => None,
        }
    }
}

impl NoticeState {
    pub fn doc(&self) -> String {
        let sealed = self.sealed.as_ref().map_or_else(
            || "null".to_string(),
            |bytes| format!("\"{}\"", hex_lower(bytes)),
        );
        format!(
            "{{\"object\":\"{}\",\"sealed\":{},\"network\":\"{}\",\"delivery\":\"{}\",\"intent_confirmed\":{},\"attempts\":{}}}",
            hex_lower(&self.object),
            sealed,
            h16(self.network),
            self.delivery.name(),
            self.intent_confirmed,
            self.attempts,
        )
    }

    pub fn from_doc(json: &Json) -> Option<Self> {
        let hex = json.get("object")?.as_str()?;
        if hex.len() > 4096 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let object = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
            .collect::<Option<Vec<_>>>()?;
        if object.is_empty() {
            return None;
        }
        let sealed = match json.get("sealed") {
            None | Some(Json::Null) => None,
            Some(Json::String(hex))
                if !hex.is_empty()
                    && hex.len() <= 4096
                    && hex.len() % 2 == 0
                    && hex.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Some(
                    (0..hex.len() / 2)
                        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
                        .collect::<Option<Vec<_>>>()?,
                )
            }
            _ => return None,
        };
        Some(Self {
            object,
            sealed,
            network: parse_h16(json.get("network")?.as_str()?)?,
            delivery: NoticeDelivery::parse(json.get("delivery")?.as_str()?)?,
            intent_confirmed: json.get("intent_confirmed")?.as_bool()?,
            attempts: u32::try_from(json.get("attempts")?.as_u64()?).ok()?,
        })
    }

    /// The `operations.get` fragment (07 §2.2). `erase_confirmed` is
    /// always null: the protocol has no remote erase proof, and a link
    /// ACK must never read as one.
    pub fn view(&self) -> String {
        format!(
            "{{\"delivery\":\"{}\",\"intent_confirmed\":{},\"erase_confirmed\":null}}",
            self.delivery.name(),
            self.intent_confirmed,
        )
    }
}

/// (entries by epoch, digests by epoch, latest object bytes).
pub(super) type RrsHistory = (
    BTreeMap<u32, Vec<RevocationEntry>>,
    BTreeMap<u32, [u8; 32]>,
    Vec<u8>,
);

/// Decodes the durable RRS1 history for ACK validation and coalescing.
/// `boundaries` carries the committed cutovers as
/// `(commit_rs_epoch, new_network)`: rs/site epochs continue across the
/// switch (04 §8.1), so each stored set verifies under its own segment's
/// network, and coverage restarts at every boundary (only a verified
/// cutover may compress entries).
pub(super) fn decode_rrs_history(
    snapshot: &super::store::Snapshot,
    sak_pubkey: &[u8; 64],
    site_id: u64,
    network: u64,
    boundaries: &[(u32, u64)],
) -> Result<RrsHistory, String> {
    let mut history = BTreeMap::new();
    let mut digests = BTreeMap::new();
    let mut latest = Vec::new();
    let mut previous: Option<(u32, u32, Vec<RevocationEntry>)> = None;
    let mut ordered: Vec<_> = snapshot.rrs.iter().collect();
    ordered.sort_by_key(|(epoch, _)| *epoch);
    // The configured SiteCert may still name the pre-cutover epoch, or
    // may have been replaced after a cutover. The first signed RRS1 is
    // the durable source for the initial network of this history.
    let initial_network = match ordered.first() {
        Some((_, object)) => {
            routeloom_provision::sdkv1::revocation::revocation_object_decode(object)
                .map_err(|e| format!("stored RRS1 corrupt: {e}"))?
                .network
        }
        None => network,
    };
    if (initial_network & 0xffff_ffff) != (network & 0xffff_ffff)
        || boundaries.last().map_or(initial_network, |(_, net)| *net) != network
    {
        return Err("stored RRS1 history network disagrees with active site".into());
    }
    for (epoch, object) in ordered {
        let expected = boundaries
            .iter()
            .filter(|(at, _)| *at <= *epoch)
            .map(|(_, network)| *network)
            .last()
            .unwrap_or(initial_network);
        let boundary = boundaries.iter().any(|(at, _)| at == epoch);
        let (set, verified) = routeloom_provision::sdkv1::revocation::revocation_object_verify(
            object, sak_pubkey, site_id, expected,
        )
        .map_err(|e| format!("stored RRS1 corrupt: {e}"))?;
        if !verified || set.rs_epoch != *epoch {
            return Err(format!(
                "stored RRS1 at epoch {epoch} fails site signature or binding"
            ));
        }
        if let Some((prior_epoch, prior_floor, prior_entries)) = &previous {
            if epoch <= prior_epoch || (!boundary && set.site_epoch_floor < *prior_floor) {
                return Err(format!("stored RRS1 history regresses at epoch {epoch}"));
            }
            if boundary {
                if set.site_epoch_floor != (expected >> 32) as u32 {
                    return Err(format!(
                        "stored RRS1 at cutover epoch {epoch} misses the new floor"
                    ));
                }
            } else if !rrs_covers(prior_entries, &set.entries) {
                return Err(format!("stored RRS1 history regresses at epoch {epoch}"));
            }
        }
        digests.insert(*epoch, super::sha256(object));
        history.insert(*epoch, set.entries.clone());
        previous = Some((*epoch, set.site_epoch_floor, set.entries));
        latest = object.clone();
    }
    if boundaries
        .iter()
        .any(|(epoch, _)| !history.contains_key(epoch))
    {
        return Err("stored RRS1 history misses a cutover boundary".into());
    }
    Ok((history, digests, latest))
}

impl SiteAuthority {
    /// Installs the RRS1 transport (production: the P6 channel
    /// port's share of its hub; tests inject a fake). `None` means
    /// nothing is sent and every target honestly stays `unknown`.
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
    pub(super) fn persist_operation(&mut self, op: u64, now_ms: u64) {
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
    /// Notices and grants queue ahead (see `tick_cutover`); the paced
    /// dispatch below serves every kind from the one outbox.
    pub(super) fn tick_distribution(&mut self, now_ms: u64) {
        // Convergence is transport-agnostic (an empty snapshot converges
        // with no transport at all); only queueing and dispatch need one.
        self.converge_distributions(now_ms);
        if self.rrs_transport.is_none() {
            return;
        }
        self.rrs_refusals
            .retain(|(op, _, _), _| self.operations.contains_key(op));
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
            // A retired network's sets want no airtime: their targets
            // either moved (and prove on the new network) or stay
            // honestly unknown.
            if dist.network != self.id.network {
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
                if target.state == TargetState::Unknown && target.next_retry_ms > now_ms {
                    continue;
                }
                if self
                    .rrs_outbox
                    .iter()
                    .any(|o| o.op == id && o.node == target.node && o.what == OutboundKind::Rrs)
                {
                    continue;
                }
                if self
                    .rrs_refusals
                    .get(&(id, target.node, OutboundKind::Rrs))
                    .is_some_and(|(due, _)| *due > now_ms)
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
                    what: OutboundKind::Rrs,
                });
            }
        }
        // Inspect each mail at most once per tick. Refused mail leaves
        // the bounded outbox until its own retry deadline.
        let mut sent: Vec<(u64, u64, OutboundKind)> = Vec::new();
        let candidates = self.rrs_outbox.len();
        for _ in 0..candidates {
            if now_ms < self.rrs_next_dispatch_ms {
                break;
            }
            let Some(head) = self.rrs_outbox.pop_front() else {
                break;
            };
            let bytes = match head.what {
                OutboundKind::Rrs => {
                    if !self.target_still_due(head.op, head.node, now_ms) {
                        continue; // converged/retired/applied meanwhile: drop, no airtime
                    }
                    Some((self.rrs_latest_object.clone(), self.id.network))
                }
                OutboundKind::Notice => self.notice_bytes(head.op),
                OutboundKind::Prepare | OutboundKind::Commit => {
                    if !self.grant_still_due(head.op, head.node, head.what, now_ms) {
                        continue;
                    }
                    let network = self
                        .operations
                        .get(&head.op)
                        .and_then(|op| op.cutover.as_ref())
                        .map(|state| state.old_network);
                    self.grant_bytes(head.op, head.node, head.what)
                        .and_then(|bytes| network.map(|network| (bytes, network)))
                }
            };
            let Some((bytes, network)) = bytes else {
                self.rrs_refusals.remove(&(head.op, head.node, head.what));
                continue; // stale entry (phase moved, op evicted): drop, no airtime
            };
            let presealed_notice = head.what == OutboundKind::Notice
                && self
                    .operations
                    .get(&head.op)
                    .and_then(|op| op.notice.as_ref())
                    .is_some_and(|notice| notice.sealed.is_some());
            let delivered = match self.rrs_transport.as_mut() {
                Some(transport) => match head.what {
                    OutboundKind::Rrs => transport.send_rrs(head.node, &bytes),
                    OutboundKind::Notice if presealed_notice => {
                        transport.send_presealed_notice(head.node, &bytes)
                    }
                    OutboundKind::Notice => transport.send_notice(head.node, network, &bytes),
                    OutboundKind::Prepare | OutboundKind::Commit => {
                        transport.send_grant(head.node, network, &bytes)
                    }
                },
                None => false,
            };
            if !delivered {
                // Keep retry metadata outside the four-slot outbox so
                // offline targets cannot occupy every mail slot.
                let key = (head.op, head.node, head.what);
                let refusals = self.rrs_refusals.get(&key).map_or(0, |(_, count)| *count);
                let level = (refusals as usize).min(DISTRIBUTION_BACKOFF_S.len() - 1);
                let wait = DISTRIBUTION_BACKOFF_S[level].saturating_mul(1000);
                let due = now_ms.saturating_add(wait);
                self.rrs_refusals
                    .insert(key, (due, refusals.saturating_add(1)));
                continue;
            }
            self.rrs_refusals.remove(&(head.op, head.node, head.what));
            self.rrs_next_dispatch_ms = now_ms.saturating_add(DISTRIBUTION_DISPATCH_GAP_MS);
            sent.push((head.op, head.node, head.what));
        }
        let mut touched: Vec<u64> = sent.iter().map(|(op, _, _)| *op).collect();
        touched.sort_unstable();
        touched.dedup();
        for (op, node, what) in sent {
            match what {
                OutboundKind::Rrs => self.note_sent(op, node, now_ms),
                OutboundKind::Notice => self.note_notice_sent(op, now_ms),
                OutboundKind::Prepare | OutboundKind::Commit => {
                    self.note_grant_sent(op, node, now_ms)
                }
            }
        }
        for id in touched {
            self.persist_operation(id, now_ms);
        }
        // Converge what the sends (and coalescing) completed.
        self.converge_distributions(now_ms);
    }

    /// Queues pending RemovalNotices ahead of grants and RRS1 fan-out
    /// (04 §7.1: the notice goes first). Best-effort: at most
    /// [`NOTICE_SEND_MAX`] transport sends, then the target is on its
    /// own until its ZT recovery.
    pub(super) fn queue_notices(&mut self, time: super::group_keys::HostTime) {
        if self
            .rrs_transport
            .as_ref()
            .map_or(true, |transport| !transport.carries_notice())
        {
            return;
        }
        let mut ops: Vec<u64> = self.operations.keys().copied().collect();
        ops.sort_by_key(|id| std::cmp::Reverse(*id));
        for id in ops {
            if self.rrs_outbox.len() >= DISTRIBUTION_OUTBOX_MAX {
                break;
            }
            let due = match self.operations.get(&id) {
                Some(op) => match op.notice.as_ref() {
                    Some(notice)
                        if (notice.network == self.id.network || notice.sealed.is_some())
                            && matches!(
                                notice.delivery,
                                NoticeDelivery::Pending | NoticeDelivery::Sent
                            )
                            && notice.attempts < NOTICE_SEND_MAX =>
                    {
                        op.node
                    }
                    _ => continue,
                },
                None => continue,
            };
            if self
                .rrs_outbox
                .iter()
                .any(|o| o.op == id && o.what == OutboundKind::Notice)
            {
                continue;
            }
            if self
                .rrs_refusals
                .get(&(id, due, OutboundKind::Notice))
                .is_some_and(|(retry_at, _)| *retry_at > time.unix_ms)
            {
                continue;
            }
            // No live or retained binding (and the row being removed,
            // none can form): mark `unreachable` instead of retrying
            // past the best-effort window. Fakes always seal, so
            // their queueing is unchanged.
            let sealable = self
                .operations
                .get(&id)
                .and_then(|op| op.notice.as_ref())
                .is_some_and(|notice| notice.sealed.is_some())
                || self.rrs_transport.as_ref().is_some_and(|transport| {
                    transport.notice_sealable(due, self.id.network, time.mono_ms)
                });
            if !sealable {
                self.note_notice_unreachable(id, time.unix_ms);
                continue;
            }
            self.rrs_outbox.push_back(OutboundRrs {
                op: id,
                node: due,
                what: OutboundKind::Notice,
            });
        }
    }

    /// Marks a notice `unreachable`: no authority context exists for
    /// the removed binding, so the direct send cannot proceed (the
    /// RRS1 fan-out still carries the revocation). Silent, like the
    /// revoke-time and cutover-commit markings.
    fn note_notice_unreachable(&mut self, op: u64, now_ms: u64) {
        let changed = match self.operations.get_mut(&op) {
            Some(operation) => match operation.notice.as_mut() {
                Some(notice)
                    if matches!(
                        notice.delivery,
                        NoticeDelivery::Pending | NoticeDelivery::Sent
                    ) =>
                {
                    notice.delivery = NoticeDelivery::Unreachable;
                    true
                }
                _ => false,
            },
            None => false,
        };
        if changed {
            self.persist_operation(op, now_ms);
        }
    }

    /// Resolves one queued notice to `(bytes, network)`. A notice whose
    /// op retired it meanwhile resolves to nothing and drops.
    fn notice_bytes(&self, op: u64) -> Option<(Vec<u8>, u64)> {
        let operation = self.operations.get(&op)?;
        let notice = operation.notice.as_ref()?;
        if (notice.network != self.id.network && notice.sealed.is_none())
            || !matches!(
                notice.delivery,
                NoticeDelivery::Pending | NoticeDelivery::Sent
            )
            || notice.attempts >= NOTICE_SEND_MAX
        {
            return None;
        }
        Some((
            notice
                .sealed
                .clone()
                .unwrap_or_else(|| notice.object.clone()),
            notice.network,
        ))
    }

    /// Records a notice send: the first one moves Pending to Sent with
    /// its `member.removal_notified` event; resends just count.
    fn note_notice_sent(&mut self, op: u64, now_ms: u64) {
        let (node, generation) = match self.operations.get(&op) {
            Some(operation) => (operation.node, operation.generation),
            None => return,
        };
        let first = match self.operations.get_mut(&op) {
            Some(operation) => match operation.notice.as_mut() {
                Some(notice) => {
                    notice.attempts = notice.attempts.saturating_add(1);
                    if notice.delivery == NoticeDelivery::Pending {
                        notice.delivery = NoticeDelivery::Sent;
                        true
                    } else {
                        false
                    }
                }
                None => return,
            },
            None => return,
        };
        if first {
            self.event(
                now_ms,
                format!(
                    "\"kind\":\"member.removal_notified\",\"device_id\":\"{}\",\"generation\":{generation},\"route\":\"authority_direct\",\"intent_confirmed\":false",
                    h16(node)
                ),
            );
        }
    }

    /// Records a NoticeAccepted receipt (type 5 sub 3, called by the P5
    /// authority channel with the context-bound node/generation/
    /// network): the removed binding's notice hash must match exactly,
    /// and the cited set cannot be from our future. This confirms the
    /// durable intent — never the erase. Returns true when a notice
    /// moved to confirmed.
    pub fn handle_notice_accepted(
        &mut self,
        node: u64,
        generation: u32,
        network: u64,
        rs_epoch: u32,
        notice_sha256: &[u8; 32],
        now_ms: u64,
    ) -> bool {
        // The device proves a set we issued: a newer citation than our
        // latest is a forgery (older is fine — the accept may predate
        // later revokes or the cutover).
        if rs_epoch > self.rs_epoch {
            return false;
        }
        let ids: Vec<u64> = self.operations.keys().copied().collect();
        for id in ids {
            let matched = self.operations.get(&id).is_some_and(|op| {
                op.kind == "revoke" && op.node == node && op.generation == generation
            }) && self
                .operations
                .get(&id)
                .and_then(|op| op.notice.as_ref())
                .is_some_and(|notice| {
                    notice.network == network
                        && !notice.intent_confirmed
                        && super::sha256(&notice.object) == *notice_sha256
                });
            if !matched {
                continue;
            }
            let mut updated = match self.operations.get(&id).cloned() {
                Some(op) => op,
                None => continue,
            };
            if let Some(notice) = updated.notice.as_mut() {
                notice.intent_confirmed = true;
            }
            let batch = Batch {
                docs: vec![(DocKind::Operation, h16(updated.id), Some(updated.doc()))],
                ..Batch::default()
            };
            match self.store.commit(&batch) {
                Ok(()) => {
                    self.operations.insert(id, updated);
                    self.event(
                        now_ms,
                        format!(
                            "\"kind\":\"member.removal_notified\",\"device_id\":\"{}\",\"generation\":{generation},\"route\":\"authority_direct\",\"intent_confirmed\":true",
                            h16(node)
                        ),
                    );
                    return true;
                }
                Err(error) => {
                    self.store_error(now_ms, &error);
                    return false;
                }
            }
        }
        false
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
            target.attempts = target.attempts.saturating_add(1);
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
        let Some(live) = self.devices.get(&node) else {
            return false;
        };
        if !live.member || live.generation != generation || network != self.id.network {
            return false;
        }
        let live_kid = live.kid;
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
            let mut updated = match self.operations.get(&id).cloned() {
                Some(op) => op,
                None => continue,
            };
            let changed = match updated.distribution.as_mut() {
                Some(dist) => {
                    let mut changed = false;
                    for target in dist.targets.iter_mut() {
                        if target.node == node
                            && target.generation == generation
                            && target.kid == live_kid
                            && target.network == network
                            && matches!(target.state, TargetState::Pending | TargetState::Unknown)
                        {
                            target.state = TargetState::Applied;
                            target.ack_rs_epoch = Some(rs_epoch);
                            changed = true;
                        }
                    }
                    changed
                }
                None => false,
            };
            if changed {
                if updated
                    .distribution
                    .as_ref()
                    .is_some_and(|dist| dist.counts().2 == 0)
                {
                    if let Some(dist) = updated.distribution.as_mut() {
                        dist.state = DistState::Converged;
                    }
                }
                let batch = Batch {
                    docs: vec![(DocKind::Operation, h16(updated.id), Some(updated.doc()))],
                    ..Batch::default()
                };
                match self.store.commit(&batch) {
                    Ok(()) => {
                        self.operations.insert(id, updated);
                        moved = true;
                    }
                    Err(error) => self.store_error(now_ms, &error),
                }
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
            let mut row = super::super::store::DeviceRow::default();
            row.node = node;
            row.member = true;
            row.generation = 1;
            auth.devices.insert(node, row);
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

    /// A refused head gets its own backoff outside the outbox, so one
    /// channel-less member cannot head-of-line block
    /// the members behind it (live E2E cutover with an offline gateway).
    #[test]
    fn refusal_parks_one_head_without_stalling_the_outbox() {
        use std::sync::{Arc, Mutex};
        struct RefuseOne {
            refused: u64,
            sent: Arc<Mutex<Vec<u64>>>,
        }
        impl RevocationTransport for RefuseOne {
            fn send_rrs(&mut self, node: u64, _object: &[u8]) -> bool {
                if node == self.refused {
                    return false;
                }
                self.sent.lock().unwrap().push(node);
                true
            }
        }
        fn target(node: u64) -> DistributionTarget {
            DistributionTarget {
                node,
                kid: [0xAA; 32],
                generation: 1,
                network: super::super::testkit::network(),
                state: TargetState::Pending,
                attempts: 0,
                next_retry_ms: 0,
                ack_rs_epoch: None,
            }
        }
        const T0: u64 = 1_790_000_000_000;
        const REFUSED: u64 = 0x00A1_0000_0000_0001;
        const ONLINE: u64 = 0x00A1_0000_0000_0002;
        const LATE: u64 = 0x00A1_0000_0000_0003;
        let mut auth = super::super::testkit::authority(
            Box::<super::super::store::MemoryStore>::default(),
            T0,
        );
        auth.operations.insert(
            7,
            super::super::records::Operation {
                id: 7,
                kind: "revoke".to_string(),
                node: 0x00A1_0000_0000_0009,
                generation: 1,
                member_cert_serial: 0,
                rs_epoch: 2,
                gk_from: 0,
                gk_to: 0,
                created_ms: T0,
                gk_cause: String::new(),
                gk_end: String::new(),
                distribution: Some(OperationDistribution {
                    state: DistState::Distributing,
                    rs_epoch: 2,
                    network: super::super::testkit::network(),
                    object_sha256: [0xBB; 32],
                    targets: vec![target(REFUSED), target(ONLINE)],
                    overflow: 0,
                }),
                cutover: None,
                notice: None,
            },
        );
        auth.rrs_latest_object = vec![9u8; 32];
        let sent = Arc::new(Mutex::new(Vec::new()));
        auth.set_rrs_transport(Some(Box::new(RefuseOne {
            refused: REFUSED,
            sent: sent.clone(),
        })));

        // The refused head parks; the online member behind it is served
        // in the same pass.
        auth.tick_distribution(T0);
        assert_eq!(*sent.lock().unwrap(), vec![ONLINE]);
        let dist = auth
            .operations
            .get(&7)
            .unwrap()
            .distribution
            .clone()
            .unwrap();
        assert_eq!(dist.targets[0].state, TargetState::Pending);
        assert_eq!(dist.targets[1].state, TargetState::Unknown);
        assert_eq!(dist.targets[1].attempts, 1);

        // A new due target behind the parked head can dispatch before
        // that head's retry deadline.
        auth.operations
            .get_mut(&7)
            .unwrap()
            .distribution
            .as_mut()
            .unwrap()
            .targets
            .push(target(LATE));
        auth.tick_distribution(T0 + DISTRIBUTION_DISPATCH_GAP_MS);
        assert_eq!(*sent.lock().unwrap(), vec![ONLINE, LATE]);

        // Past the backoff the refused head retries (and refuses
        // again) while the online member sends again.
        auth.tick_distribution(T0 + 6_000);
        assert_eq!(*sent.lock().unwrap(), vec![ONLINE, LATE, ONLINE]);
    }

    #[test]
    fn refused_heads_free_the_bounded_outbox_for_an_online_target() {
        use std::sync::{Arc, Mutex};
        struct RefuseOffline(Arc<Mutex<Vec<u64>>>);
        impl RevocationTransport for RefuseOffline {
            fn send_rrs(&mut self, node: u64, _object: &[u8]) -> bool {
                self.0.lock().unwrap().push(node);
                node == ONLINE
            }
        }
        const T0: u64 = 1_790_000_000_000;
        const NODE: u64 = 0x00A1_0000_0000_0001;
        const ONLINE: u64 = 0x00A1_0000_0000_0002;
        let mut auth = super::super::testkit::authority(
            Box::<super::super::store::MemoryStore>::default(),
            T0,
        );
        auth.operations.insert(
            7,
            super::super::records::Operation {
                id: 7,
                kind: "revoke".to_string(),
                node: 0x00A1_0000_0000_0009,
                generation: 1,
                member_cert_serial: 0,
                rs_epoch: 2,
                gk_from: 0,
                gk_to: 0,
                created_ms: T0,
                gk_cause: String::new(),
                gk_end: String::new(),
                distribution: Some(OperationDistribution {
                    state: DistState::Distributing,
                    rs_epoch: 2,
                    network: super::super::testkit::network(),
                    object_sha256: [0xBB; 32],
                    targets: vec![DistributionTarget {
                        node: NODE,
                        kid: [0xAA; 32],
                        generation: 1,
                        network: super::super::testkit::network(),
                        state: TargetState::Pending,
                        attempts: 0,
                        next_retry_ms: 0,
                        ack_rs_epoch: None,
                    }],
                    overflow: 0,
                }),
                cutover: None,
                notice: None,
            },
        );
        auth.rrs_latest_object = vec![9u8; 32];
        let attempts = Arc::new(Mutex::new(Vec::new()));
        auth.set_rrs_transport(Some(Box::new(RefuseOffline(attempts.clone()))));

        auth.tick_distribution(T0);
        assert_eq!(*attempts.lock().unwrap(), vec![NODE]);
        let targets = &mut auth
            .operations
            .get_mut(&7)
            .unwrap()
            .distribution
            .as_mut()
            .unwrap()
            .targets;
        for node in [NODE + 2, NODE + 3, NODE + 4, ONLINE] {
            targets.push(DistributionTarget {
                node,
                kid: [0xAA; 32],
                generation: 1,
                network: super::super::testkit::network(),
                state: TargetState::Pending,
                attempts: 0,
                next_retry_ms: 0,
                ack_rs_epoch: None,
            });
        }
        auth.tick_distribution(T0 + DISTRIBUTION_DISPATCH_GAP_MS);
        assert!(
            attempts.lock().unwrap().contains(&ONLINE),
            "the fifth member was served"
        );
        auth.tick_distribution(T0 + 5_000);
        assert!(
            attempts
                .lock()
                .unwrap()
                .iter()
                .filter(|&&n| n == NODE)
                .count()
                >= 2
        );
        auth.tick_distribution(T0 + 10_000);
        assert_eq!(
            attempts
                .lock()
                .unwrap()
                .iter()
                .filter(|&&n| n == NODE)
                .count(),
            2,
            "an unrelated successful send does not reset this head's backoff"
        );
        auth.tick_distribution(T0 + 15_000);
        assert_eq!(
            attempts
                .lock()
                .unwrap()
                .iter()
                .filter(|&&n| n == NODE)
                .count(),
            3
        );
    }
}
