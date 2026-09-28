//! Host site_epoch cutover (04 §7, plan P6-2 PR D).
//!
//! The single Host driver for GrantRenew distribution and the epoch
//! switch. `membership.cutover` validates the next SiteCert against the
//! configured Site CA and durably stages the next epoch — the next
//! SiteCert, one next MemberCert per live member (same generation, new
//! network), one fresh next DAMS per member and the next GK from the
//! shared P5 allocator — and only then lets the tick pace PREPAREs out.
//! 600 s after staging, with a current-revision gateway PREPARED in
//! hand, one transaction signs the next RRS1 and the CutoverCommit and
//! switches the active epoch; COMMITs then flow over the 60 s
//! old-network grace, and stragglers recover through the authenticated
//! reissue path (no KGuard), never through a rollback.
//!
//! One cutover lives at a time. A revoke during Preparing commits to
//! the current network first, then retires the target, carries the
//! issued-then-removed binding into the next RRS1, re-stages the next
//! GK under a new revision, invalidates every PREPARED and restarts the
//! window — all in the revoke's own transaction. An allow during
//! Preparing joins the snapshot the same way. `group_keys.rotate` and
//! the periodic rotation wait while a cutover prepares.
//!
//! Transport is the shared [`super::revocation::RevocationTransport`]
//! port. Cutover refuses to stage without a GrantRenew carrier. The
//! PREPARE bytes are assembled deterministically from the durable
//! snapshot so a PREPARED digest is verifiable after any restart.

use std::collections::{BTreeMap, BTreeSet};

use routeloom_join::renew::{Commit, CutoverCommit, Head, Phase, Prepare, Receipt, RouteState};
use routeloom_join::SitePackage;
use routeloom_json::Json;
use routeloom_peercred::Principal;
use routeloom_provision::sdkv1::cert::{
    cert_decode, cert_issue, cert_verify, CertClaims, CertType, CERT_MAX,
};
use routeloom_provision::sdkv1::revocation::{
    revocation_issue, RevocationEntry, RevocationReason, RevocationSet, REVOCATION_ENTRY_MAX,
};
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::fill_random;

use super::group_keys::{fresh_group_key, GkSecret, HostTime, META_HIGH_WATER};
use super::records::{h16, op_token, parse_h16, parse_hex, Operation};
use super::revocation::{
    checked_next, DistState, DistributionTarget, OperationDistribution, OutboundKind, OutboundRrs,
    TargetState as RrsTargetState, DISTRIBUTION_BACKOFF_S, DISTRIBUTION_OUTBOX_MAX,
    DISTRIBUTION_TARGET_MAX,
};
use super::store::{Batch, DeviceRow, DocKind, GroupKeyRow, RotationWrite};
use super::{store_failure, SiteAuthority, SiteError};
use crate::receive_log::hex_lower;

/// The fixed v1 preparation window: no early commit, no forced instant
/// switch (04 §7). The clock is the monotonic axis.
pub const CUTOVER_PREPARE_WINDOW_MS: u64 = 600_000;
/// Post-commit old-network delivery grace (RAM-only: a restart ends it
/// and stragglers fall back to the ZT reissue).
pub const CUTOVER_GRACE_MS: u64 = 60_000;
/// Held gateway COMMITs flush once this much grace remains: the
/// gateway needs ~15 s (a possible re-handshake + COMMIT + adopt +
/// reboot + re-adopt), and one dead member must not wedge the site.
pub const CUTOVER_GATEWAY_FLUSH_MS: u64 = 20_000;
/// RouteState queries go out only in this tail of the prepare window
/// (04 §7): reports must be fresh at commit, and route leases run
/// tens of seconds — asking earlier only burns shared transfer slots
/// for answers that expire before they can steer anything.
pub const CUTOVER_ROUTE_QUERY_WINDOW_MS: u64 = 60_000;
/// Grant snapshot cap, the same P6 profile as RRS distribution (~100
/// boards plus headroom, gateways included). The live-member cap
/// ([`super::group_keys::MEMBER_CAP`]) already enforces it; a snapshot
/// past it refuses instead of truncating.
pub const CUTOVER_TARGET_MAX: usize = 128;
/// Gateway PREPAREDs (at the latest revision) required to commit.
pub const CUTOVER_GATEWAY_MIN: usize = 1;
/// `meta` key for the committed-epoch timeline: concatenated
/// `commit_rs_epoch:u32-BE || new_network:u64-BE` records, append-only.
/// It lets `open` validate the mixed-network RRS1 history even after
/// the cutover operations themselves are evicted.
pub const META_CUTOVER_EPOCHS: &str = "cutover_epochs";
/// `meta` key for the active SiteCert bytes once a cutover committed.
/// Absent until the first commit; the setup cert stays the stable
/// identity (site/low32/SAK) either way.
pub const META_ACTIVE_SITE_CERT: &str = "active_site_cert";

/// `membership.cutover` input (07 §2.2, ADMIN).
pub struct CutoverRequest {
    pub expected_site_epoch: u32,
    pub next_site_cert: Vec<u8>,
    pub key: String,
}

fn reason_from_u8(value: u8) -> Option<RevocationReason> {
    Some(match value {
        1 => RevocationReason::Removed,
        2 => RevocationReason::Lost,
        3 => RevocationReason::Replaced,
        4 => RevocationReason::Blocked,
        _ => return None,
    })
}

/// Per-target grant state. `Pending` never left the Host; `Unknown`
/// was sent but never proved; both count as `unknown` in the API.
/// `Recovered` missed the COMMIT and rejoined through the ZT reissue
/// (04 §7) — converged like `Applied`, never confused with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantState {
    Pending,
    Unknown,
    Prepared,
    Applied,
    Recovered,
    Retired,
}

impl GrantState {
    fn name(self) -> &'static str {
        match self {
            GrantState::Pending => "pending",
            GrantState::Unknown => "unknown",
            GrantState::Prepared => "prepared",
            GrantState::Applied => "applied",
            GrantState::Recovered => "recovered",
            GrantState::Retired => "retired",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(GrantState::Pending),
            "unknown" => Some(GrantState::Unknown),
            "prepared" => Some(GrantState::Prepared),
            "applied" => Some(GrantState::Applied),
            "recovered" => Some(GrantState::Recovered),
            "retired" => Some(GrantState::Retired),
            _ => None,
        }
    }
}

/// One staged grant: the target binding plus its next-epoch secrets.
/// The DAMS rides the DB under the existing custody (0600 SQLite, like
/// every live DAMS); the API never exports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverTarget {
    pub node: u64,
    pub kid: [u8; 32],
    pub generation: u32,
    pub role: u8,
    pub gateway: bool,
    pub member_cert: Vec<u8>,
    pub member_cert_serial: u32,
    pub dams: [u8; 32],
    pub state: GrantState,
    /// Latest revision this target PREPAREDed (0 = never).
    pub prepared_revision: u32,
    pub attempts: u32,
    pub next_retry_ms: u64,
}

impl CutoverTarget {
    fn doc(&self) -> String {
        format!(
            "{{\"node\":\"{}\",\"kid\":\"{}\",\"generation\":{},\"role\":{},\"gateway\":{},\"member_cert\":\"{}\",\"member_cert_serial\":{},\"dams\":\"{}\",\"state\":\"{}\",\"prepared_revision\":{},\"attempts\":{},\"next_retry_ms\":{}}}",
            h16(self.node),
            hex_lower(&self.kid),
            self.generation,
            self.role,
            self.gateway,
            hex_lower(&self.member_cert),
            self.member_cert_serial,
            hex_lower(&self.dams),
            self.state.name(),
            self.prepared_revision,
            self.attempts,
            self.next_retry_ms,
        )
    }

    fn from_doc(json: &Json) -> Option<Self> {
        let kid = parse_hex(json.get("kid")?.as_str()?, 32)?;
        let cert_hex = json.get("member_cert")?.as_str()?;
        if cert_hex.len() % 2 != 0
            || cert_hex.len() > CERT_MAX * 2
            || !cert_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        let member_cert = (0..cert_hex.len() / 2)
            .map(|i| u8::from_str_radix(&cert_hex[2 * i..2 * i + 2], 16).ok())
            .collect::<Option<Vec<_>>>()?;
        if member_cert.is_empty() || member_cert.len() > CERT_MAX {
            return None;
        }
        let dams = parse_hex(json.get("dams")?.as_str()?, 32)?;
        Some(Self {
            node: parse_h16(json.get("node")?.as_str()?)?,
            kid: kid.try_into().ok()?,
            generation: u32::try_from(json.get("generation")?.as_u64()?).ok()?,
            role: u8::try_from(json.get("role")?.as_u64()?).ok()?,
            gateway: json.get("gateway")?.as_bool()?,
            member_cert,
            member_cert_serial: u32::try_from(json.get("member_cert_serial")?.as_u64()?).ok()?,
            dams: dams.try_into().ok()?,
            state: GrantState::parse(json.get("state")?.as_str()?)?,
            prepared_revision: u32::try_from(json.get("prepared_revision")?.as_u64()?).ok()?,
            attempts: u32::try_from(json.get("attempts")?.as_u64()?).ok()?,
            next_retry_ms: json.get("next_retry_ms")?.as_u64()?,
        })
    }
}

/// One target's RAM-only route plan for leaf-first COMMIT dispatch
/// (04 §7). Reports bind the query id the Host sent; `stored` is the
/// verified COMMIT_STORED receipt (ordering only — never Applied
/// evidence); `deferred` is the recorded layer-deadline cut. None of
/// it is durable: a restart ends the grace the plan paces.
#[derive(Clone, Debug, Default)]
pub struct CutoverRoutePlan {
    /// Latest query id sent (0 = none).
    pub query_id: u32,
    /// Unanswered-query rounds (shared backoff pacing).
    pub query_attempts: u32,
    /// Adopted report, if any, with its receive time and revision.
    pub report: Option<RouteReport>,
    /// A child stored COMMIT after this report; only a new answer may
    /// release an unsent COMMIT through the changed tree.
    pub recheck_due: bool,
    /// Verified COMMIT_STORED (same cutover/revision/digest).
    pub stored: bool,
    /// Cut by a layer deadline (stays unknown; ZT recovers it).
    pub deferred: bool,
}

/// One adopted RouteState report (phase 6, mode 1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteReport {
    pub root: u64,
    pub parent: u64,
    pub boot: u32,
    pub stamp: u32,
    pub query_id: u32,
    pub lease_ms: u32,
    pub revision: u32,
    pub recv_mono_ms: u64,
    pub unavailable: bool,
}

/// No RouteState query id is ever 0 (the codec rejects it); the
/// sequence skips it on wrap.
pub const ROUTE_QUERY_FIRST_ID: u32 = 1;

impl CutoverRoutePlan {
    /// A report steers dispatch only while it answers the current
    /// revision and its route lease still covers `now_mono`.
    fn usable(&self, revision: u32, now_mono: u64) -> Option<RouteReport> {
        let report = self.report?;
        if report.unavailable || report.revision != revision {
            return None;
        }
        if report.recv_mono_ms.saturating_add(report.lease_ms as u64) <= now_mono {
            return None;
        }
        Some(report)
    }

    /// Confirmed for ordering: stored, applied, recovered, or cut
    /// by a deadline. Revocation confirms separately (the target row,
    /// not the plan).
    fn settled(&self, state: GrantState) -> bool {
        self.stored
            || self.deferred
            || state == GrantState::Applied
            || state == GrantState::Recovered
    }
}

/// The uplink forest over the current targets, rebuilt from the
/// RAM route plans on every use (04 §7): `depths` resolves each
/// target (gateways are roots at 0; `None` is unresolvable — no
/// usable report, a parent that is not a live target, a revoked
/// link, a cycle, a root mismatch — and dispatches in the deepest
/// layer); `h` is the deepest non-gateway layer (unresolved
/// non-gateway targets count as layer 1, so H is 0 only when no
/// non-gateway target can still move); `children` links each parent
/// to its reporting children for the release gate.
struct RouteTree {
    depths: BTreeMap<u64, Option<u32>>,
    h: u32,
    children: BTreeMap<u64, Vec<u64>>,
    parents: BTreeMap<u64, u64>,
}

fn route_tree(
    targets: &[CutoverTarget],
    plans: &BTreeMap<(u64, u64), CutoverRoutePlan>,
    op: u64,
    revision: u32,
    now_mono: u64,
) -> RouteTree {
    let live: BTreeSet<u64> = targets.iter().map(|t| t.node).collect();
    // Unusable transit (04 §7): a revoked — or recovered-new-network —
    // node relays no old-context COMMIT, so no route resolves through
    // one and children of one defer to the ZT reissue instead.
    let retired: BTreeSet<u64> = targets
        .iter()
        .filter(|t| matches!(t.state, GrantState::Retired | GrantState::Recovered))
        .map(|t| t.node)
        .collect();
    let gateways: BTreeSet<u64> = targets
        .iter()
        .filter(|t| t.gateway)
        .map(|t| t.node)
        .collect();
    let mut links: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for target in targets {
        if target.gateway {
            continue;
        }
        let Some(report) = plans
            .get(&(op, target.node))
            .and_then(|plan| plan.usable(revision, now_mono))
        else {
            continue;
        };
        if report.parent == 0 || report.parent == target.node {
            continue;
        }
        links.insert(target.node, (report.parent, report.root));
    }
    let mut depths: BTreeMap<u64, Option<u32>> = BTreeMap::new();
    for target in targets {
        if target.gateway {
            depths.insert(target.node, Some(0));
            continue;
        }
        let mut depth: u32 = 0;
        let mut cursor = target.node;
        let mut seen = BTreeSet::from([cursor]);
        let mut root = 0;
        let resolved = loop {
            let Some((parent, claimed)) = links.get(&cursor) else {
                break false;
            };
            if root == 0 {
                root = *claimed;
            }
            if retired.contains(parent) || !live.contains(parent) || !seen.insert(*parent) {
                break false;
            }
            depth = depth.saturating_add(1);
            if depth > 128 {
                break false;
            }
            if gateways.contains(parent) {
                break root == *parent;
            }
            cursor = *parent;
        };
        depths.insert(target.node, resolved.then_some(depth));
    }
    let mut parents: BTreeMap<u64, u64> = BTreeMap::new();
    let mut children: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (node, (parent, _)) in &links {
        if live.contains(parent) && !retired.contains(parent) {
            parents.insert(*node, *parent);
            children.entry(*parent).or_default().push(*node);
        }
    }
    let mut h: u32 = 0;
    for target in targets {
        if target.gateway || matches!(target.state, GrantState::Retired | GrantState::Recovered) {
            continue;
        }
        let layer = depths.get(&target.node).copied().flatten().unwrap_or(1);
        h = h.max(layer.max(1));
    }
    RouteTree {
        depths,
        h,
        children,
        parents,
    }
}

impl RouteTree {
    /// Transitive reporting subtree of `node` (cycle-guarded).
    fn descendants(&self, node: u64) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<u64> = self.children.get(&node).cloned().unwrap_or_default();
        while let Some(next) = stack.pop() {
            if !out.insert(next) {
                continue;
            }
            if let Some(kids) = self.children.get(&next) {
                stack.extend(kids.iter().copied());
            }
        }
        out.remove(&node);
        out
    }

    /// The uplink chain of `node` over usable links (partial on the
    /// first gap — a target never waits for the relay it reports
    /// through, even when the rest of its chain is unknown).
    fn ancestors(&self, node: u64) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        let mut cursor = node;
        while let Some(parent) = self.parents.get(&cursor) {
            if !out.insert(*parent) {
                break;
            }
            cursor = *parent;
        }
        out.remove(&node);
        out
    }
}

/// The durable cutover phase (04 §8.2, folded: Preparing covers the
/// store-then-distribute pair, Committed covers commit-then-activate —
/// the tick moves between them without an observable gap).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutoverPhase {
    Preparing,
    WaitingGateway,
    Committed,
    Converged,
    RecoveryPending,
}

impl CutoverPhase {
    fn name(self) -> &'static str {
        match self {
            CutoverPhase::Preparing => "preparing",
            CutoverPhase::WaitingGateway => "waiting_gateway",
            CutoverPhase::Committed => "committed",
            CutoverPhase::Converged => "converged",
            CutoverPhase::RecoveryPending => "recovery_pending",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "preparing" => Some(CutoverPhase::Preparing),
            "waiting_gateway" => Some(CutoverPhase::WaitingGateway),
            "committed" => Some(CutoverPhase::Committed),
            "converged" => Some(CutoverPhase::Converged),
            "recovery_pending" => Some(CutoverPhase::RecoveryPending),
            _ => None,
        }
    }

    fn live(self) -> bool {
        // RecoveryPending still converges — stragglers Recovered through
        // the reissue, or Retired through an explicit revoke — so it
        // stays live (and blocks the next cutover) until they settle.
        matches!(
            self,
            CutoverPhase::Preparing
                | CutoverPhase::WaitingGateway
                | CutoverPhase::Committed
                | CutoverPhase::RecoveryPending
        )
    }
}

/// The durable cutover snapshot. It rides the operation doc, so a
/// restart resumes the same cutover without consuming new epochs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverState {
    pub phase: CutoverPhase,
    pub old_network: u64,
    pub new_network: u64,
    pub expected_site_epoch: u32,
    pub new_site_epoch: u32,
    /// Prepare revision (from 1, never rewound; frozen at commit).
    pub revision: u32,
    pub next_site_cert: Vec<u8>,
    pub next_gk_epoch: u32,
    /// The operation that staged the current next GK (this cutover or a
    /// revoke that re-staged it); superseded owners close as such.
    pub gk_owner_op: u64,
    /// Membership revision pinned into every PREPARE SitePackage, so
    /// the bytes — and the PREPARED digest over them — stay stable
    /// while allows/revokes move the live revision.
    pub package_revision: u32,
    /// 0 until the commit transaction signs the next RRS1.
    pub commit_rs_epoch: u32,
    pub commit_object: Vec<u8>,
    pub commit_rrs: Vec<u8>,
    /// Issued-then-removed bindings the next RRS1 must keep refusing
    /// (04 §8.3: ACK or not, an issued grant is assumed known).
    pub carry: Vec<RevocationEntry>,
    /// Current 600 s window start (monotonic; restarted on reopen).
    pub started_mono_ms: u64,
    /// 0 until committed.
    pub commit_unix_ms: u64,
    pub targets: Vec<CutoverTarget>,
}

impl CutoverState {
    /// (prepared, applied, recovered, unknown, total) over non-retired
    /// targets; retired targets left through a later explicit revoke.
    /// Post-commit a still-Prepared target counts as unknown (04 §7):
    /// its staging never became adoption, so the ZT reissue owns it.
    /// `prepared` stays a separate readiness readout, never part of
    /// the split: post-commit total = applied + recovered + unknown.
    pub fn counts(&self) -> (u64, u64, u64, u64, u64) {
        let committed = !matches!(
            self.phase,
            CutoverPhase::Preparing | CutoverPhase::WaitingGateway
        );
        let mut prepared = 0_u64;
        let mut applied = 0_u64;
        let mut recovered = 0_u64;
        let mut unknown = 0_u64;
        for target in &self.targets {
            match target.state {
                GrantState::Prepared => {
                    prepared += 1;
                    if committed {
                        unknown += 1;
                    }
                }
                GrantState::Applied => applied += 1,
                GrantState::Recovered => recovered += 1,
                GrantState::Pending | GrantState::Unknown => unknown += 1,
                GrantState::Retired => {}
            }
        }
        let total = if committed {
            applied + recovered + unknown
        } else {
            prepared + applied + unknown
        };
        (prepared, applied, recovered, unknown, total)
    }

    pub fn doc(&self) -> String {
        let targets = self
            .targets
            .iter()
            .map(CutoverTarget::doc)
            .collect::<Vec<_>>()
            .join(",");
        let carry = self
            .carry
            .iter()
            .map(|e| {
                format!(
                    "{{\"node\":\"{}\",\"min_generation\":{},\"reason\":{}}}",
                    h16(e.node_id),
                    e.min_generation,
                    e.reason as u8
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"phase\":\"{}\",\"old_network\":\"{}\",\"new_network\":\"{}\",\"expected_site_epoch\":{},\"new_site_epoch\":{},\"revision\":{},\"next_site_cert\":\"{}\",\"next_gk_epoch\":{},\"gk_owner_op\":{},\"package_revision\":{},\"commit_rs_epoch\":{},\"commit_object\":\"{}\",\"commit_rrs\":\"{}\",\"carry\":[{carry}],\"started_mono_ms\":{},\"commit_unix_ms\":{},\"targets\":[{targets}]}}",
            self.phase.name(),
            h16(self.old_network),
            h16(self.new_network),
            self.expected_site_epoch,
            self.new_site_epoch,
            self.revision,
            hex_lower(&self.next_site_cert),
            self.next_gk_epoch,
            self.gk_owner_op,
            self.package_revision,
            self.commit_rs_epoch,
            hex_lower(&self.commit_object),
            hex_lower(&self.commit_rrs),
            self.started_mono_ms,
            self.commit_unix_ms,
        )
    }

    pub fn from_doc(json: &Json) -> Option<Self> {
        let targets = json
            .get("targets")?
            .as_array()?
            .iter()
            .map(CutoverTarget::from_doc)
            .collect::<Option<Vec<_>>>()?;
        if targets.len() > CUTOVER_TARGET_MAX {
            return None;
        }
        let carry = json
            .get("carry")?
            .as_array()?
            .iter()
            .map(|entry| {
                Some(RevocationEntry {
                    node_id: parse_h16(entry.get("node")?.as_str()?)?,
                    min_generation: u32::try_from(entry.get("min_generation")?.as_u64()?).ok()?,
                    reason: reason_from_u8(u8::try_from(entry.get("reason")?.as_u64()?).ok()?)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        if carry.len() > REVOCATION_ENTRY_MAX {
            return None;
        }
        let cert_hex = json.get("next_site_cert")?.as_str()?;
        if cert_hex.len() % 2 != 0
            || cert_hex.len() > CERT_MAX * 2
            || !cert_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        let next_site_cert = (0..cert_hex.len() / 2)
            .map(|i| u8::from_str_radix(&cert_hex[2 * i..2 * i + 2], 16).ok())
            .collect::<Option<Vec<_>>>()?;
        if next_site_cert.is_empty() || next_site_cert.len() > CERT_MAX {
            return None;
        }
        let commit_hex = json.get("commit_object")?.as_str()?;
        if !commit_hex.is_empty()
            && commit_hex.len() != routeloom_join::renew::COMMIT_OBJECT_SIZE * 2
        {
            return None;
        }
        let commit_object = if commit_hex.is_empty() {
            Vec::new()
        } else {
            parse_hex(commit_hex, commit_hex.len() / 2)?
        };
        let rrs_hex = json.get("commit_rrs")?.as_str()?;
        if rrs_hex.len() % 2 != 0
            || rrs_hex.len() > routeloom_provision::sdkv1::revocation::REVOCATION_OBJECT_MAX * 2
        {
            return None;
        }
        let commit_rrs = if rrs_hex.is_empty() {
            Vec::new()
        } else {
            parse_hex(rrs_hex, rrs_hex.len() / 2)?
        };
        Some(Self {
            phase: CutoverPhase::parse(json.get("phase")?.as_str()?)?,
            old_network: parse_h16(json.get("old_network")?.as_str()?)?,
            new_network: parse_h16(json.get("new_network")?.as_str()?)?,
            expected_site_epoch: u32::try_from(json.get("expected_site_epoch")?.as_u64()?).ok()?,
            new_site_epoch: u32::try_from(json.get("new_site_epoch")?.as_u64()?).ok()?,
            revision: u32::try_from(json.get("revision")?.as_u64()?).ok()?,
            next_site_cert,
            next_gk_epoch: u32::try_from(json.get("next_gk_epoch")?.as_u64()?).ok()?,
            gk_owner_op: json.get("gk_owner_op")?.as_u64()?,
            package_revision: u32::try_from(json.get("package_revision")?.as_u64()?).ok()?,
            commit_rs_epoch: u32::try_from(json.get("commit_rs_epoch")?.as_u64()?).ok()?,
            commit_object,
            commit_rrs,
            carry,
            started_mono_ms: json.get("started_mono_ms")?.as_u64()?,
            commit_unix_ms: json.get("commit_unix_ms")?.as_u64()?,
            targets,
        })
    }
}

/// Parses the committed-epoch timeline (`META_CUTOVER_EPOCHS`): strictly
/// increasing `commit_rs_epoch` values with their new networks.
pub(super) fn parse_cutover_epochs(bytes: &[u8]) -> Option<Vec<(u32, u64)>> {
    if bytes.len() % 12 != 0 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in bytes.chunks_exact(12) {
        let epoch = u32::from_be_bytes(chunk[0..4].try_into().ok()?);
        let network = u64::from_be_bytes(chunk[4..12].try_into().ok()?);
        if epoch == 0 || network == 0 {
            return None;
        }
        if out
            .last()
            .is_some_and(|(prev, _): &(u32, u64)| *prev >= epoch)
        {
            return None;
        }
        out.push((epoch, network));
    }
    Some(out)
}

/// What a revoke folds into the live cutover: the updated snapshot,
/// the superseded GK owner, the replacement staged key and the revoke
/// operation's own GK epochs. The caller commits it, then publishes.
pub(super) struct RevokeCutoverEffect {
    pub updated: Option<Operation>,
    pub superseded_owner: Option<Operation>,
    pub staged: Option<(u32, [u8; 32])>,
    pub delete_staged: Vec<u32>,
    pub gk_epochs: (u32, u32),
    pub revision: Option<u32>,
}

impl RevokeCutoverEffect {
    fn none(active: u32) -> Self {
        Self {
            updated: None,
            superseded_owner: None,
            staged: None,
            delete_staged: Vec::new(),
            gk_epochs: (active, active),
            revision: None,
        }
    }
}

/// A fresh nonzero 32 B secret from the Host CSPRNG (04 §5.3: the
/// cutover DAMS and GK are never zero, never reused, never derived
/// from the old ones).
fn fresh_secret() -> Result<[u8; 32], SiteError> {
    loop {
        let mut out = [0_u8; 32];
        fill_random(&mut out)
            .map_err(|e| SiteError::new("AUTHORITY_ERROR", format!("host entropy failed: {e}")))?;
        if out.iter().any(|v| *v != 0) {
            return Ok(out);
        }
    }
}

impl SiteAuthority {
    /// The live cutover operation, if any (at most one exists: start
    /// refuses a second, and only a terminal phase ends one).
    pub(super) fn live_cutover(&self) -> Option<u64> {
        self.operations.values().find_map(|op| {
            op.cutover.as_ref().and_then(|state| {
                if state.phase.live() {
                    Some(op.id)
                } else {
                    None
                }
            })
        })
    }

    /// True while a cutover stages below the commit: `group_keys.rotate`
    /// and the periodic rotation wait it out, and revokes/allows fold
    /// their snapshot changes into the same transactions.
    pub(super) fn cutover_blocks_rotate(&self) -> bool {
        self.operations.values().any(|op| {
            op.cutover.as_ref().is_some_and(|state| {
                matches!(
                    state.phase,
                    CutoverPhase::Preparing | CutoverPhase::WaitingGateway
                )
            })
        })
    }

    /// The old-network delivery grace for the future P5 channel
    /// adapter: `(old_network, until_mono_ms)`. RAM-only — a restart
    /// ends it and stragglers fall back to the ZT reissue.
    pub fn cutover_grace(&self) -> Option<(u64, u64)> {
        (self.cutover_grace_network != 0)
            .then_some((self.cutover_grace_network, self.cutover_grace_until_mono))
    }

    /// `membership.cutover` (04 §7, 07 §2.2). Validates everything
    /// before anything commits — the epoch step, the next SiteCert
    /// under the configured Site CA, the snapshot, every allocator —
    /// then stages the whole next epoch in one transaction. Nothing is
    /// sent before that commit; the tick paces PREPAREs after it.
    pub fn cutover(
        &mut self,
        principal: impl Into<Principal>,
        request: CutoverRequest,
        time: HostTime,
    ) -> Result<String, SiteError> {
        let principal = principal.into();
        let now_ms = time.unix_ms;
        let digest = sha256(
            format!(
                "membership.cutover|{}|{}",
                request.expected_site_epoch,
                hex_lower(&sha256(&request.next_site_cert)),
            )
            .as_bytes(),
        );
        if let Some(answer) = self.idempotent(&principal, &request.key, &digest) {
            return answer;
        }
        let current_epoch = self.id.site_claims.site_epoch;
        if request.expected_site_epoch != current_epoch {
            return Err(SiteError::new(
                "CONFLICT",
                "expected_site_epoch does not match the active epoch",
            )
            .with(format!("\"site_epoch\":{current_epoch}")));
        }
        if let Some(live) = self.live_cutover() {
            return Err(SiteError::new(
                "CONFLICT",
                "a site_epoch cutover is already live; v1 runs one at a time",
            )
            .with(format!("\"operation_id\":\"{}\"", op_token(live))));
        }
        let new_epoch = current_epoch.checked_add(1).ok_or_else(|| {
            SiteError::new(
                "AUTHORITY_ERROR",
                "site epoch exhausted; safe maintenance required",
            )
        })?;
        let Some(ca) = self.id.site_ca_pubkey else {
            return Err(SiteError::new(
                "CUTOVER_CERT_REQUIRED",
                "no Site CA is configured; register one to validate the next SiteCert",
            ));
        };
        let next_claims = match cert_verify(&request.next_site_cert, &ca) {
            Ok((claims, true)) => claims,
            _ => {
                return Err(SiteError::new(
                    "INVALID_ARGUMENT",
                    "the next SiteCert does not verify under the configured Site CA",
                ));
            }
        };
        let current = &self.id.site_claims;
        if next_claims.cert_type != CertType::Site
            || next_claims.issuer != current.issuer
            || next_claims.subject != current.subject
            || next_claims.pubkey != current.pubkey
            || next_claims.network_low32 != current.network_low32
            || next_claims.usage != current.usage
            || next_claims.site_epoch != new_epoch
        {
            return Err(SiteError::new(
                "INVALID_ARGUMENT",
                "the next SiteCert must keep issuer / site / SAK / low32 / usage and step the epoch by exactly one",
            ));
        }
        if self
            .rrs_transport
            .as_ref()
            .is_none_or(|transport| !transport.carries_grant())
        {
            return Err(SiteError::new(
                "CUTOVER_UNAVAILABLE",
                "the GrantRenew carrier is unavailable for this site",
            )
            .retry());
        }
        let old_network = self.id.network;
        let new_network = (u64::from(new_epoch) << 32) | u64::from(next_claims.network_low32);
        let mut members: Vec<u64> = self
            .devices
            .values()
            .filter(|row| row.member)
            .map(|row| row.node)
            .collect();
        members.sort_unstable();
        if members.len() > CUTOVER_TARGET_MAX {
            return Err(SiteError::new(
                "NO_CAPACITY",
                format!(
                    "{} live members exceed the {CUTOVER_TARGET_MAX} cutover snapshot cap; revoke extras first (targets are never truncated)",
                    members.len()
                ),
            )
            .retry());
        }
        // Every allocator is checked before anything commits: one serial
        // per next MemberCert, the next GK epoch from the shared P5
        // high-water mark.
        if u32::try_from(members.len())
            .ok()
            .and_then(|n| self.next_serial.checked_add(n))
            .is_none()
        {
            return Err(SiteError::new(
                "AUTHORITY_ERROR",
                "member certificate serial exhausted",
            ));
        }
        let staged_epoch = self
            .gks
            .next_epoch()
            .map_err(|message| SiteError::new("AUTHORITY_ERROR", message))?;
        let staged_key =
            fresh_group_key().map_err(|message| SiteError::new("AUTHORITY_ERROR", message))?;
        if staged_key.iter().all(|v| *v == 0) {
            return Err(SiteError::new(
                "AUTHORITY_ERROR",
                "staged group key is zero; entropy failure",
            ));
        }
        let op_id = self.checked_next_op_id()?;
        // The next MemberCerts: same node, key, generation and role on
        // the new network — a cutover never reassigns (04 §5.3).
        let mut serial = self.next_serial;
        let mut targets = Vec::with_capacity(members.len());
        for node in &members {
            let row = &self.devices[node];
            let pubkey = cert_decode(&row.member_cert)
                .map_err(|_| {
                    SiteError::new("AUTHORITY_ERROR", "a live member cert does not decode")
                })?
                .pubkey;
            let claims = CertClaims {
                cert_type: CertType::Member,
                issuer: self.id.site_id,
                subject: *node,
                pubkey,
                network: new_network,
                role: u32::from(row.role),
                assignment_generation: row.generation,
                site_epoch: new_epoch,
                serial,
                ..CertClaims::default()
            };
            let member_cert = cert_issue(&claims, self.sak.as_ref()).map_err(|e| {
                SiteError::new(
                    "AUTHORITY_ERROR",
                    format!("next MemberCert issue failed: {e}"),
                )
            })?;
            let dams = fresh_secret()?;
            let gateway = self.id.gateways[..usize::from(self.id.gateway_count)].contains(node);
            targets.push(CutoverTarget {
                node: *node,
                kid: row.kid,
                generation: row.generation,
                role: row.role,
                gateway,
                member_cert,
                member_cert_serial: serial,
                dams,
                state: GrantState::Pending,
                prepared_revision: 0,
                attempts: 0,
                next_retry_ms: 0,
            });
            serial = serial.checked_add(1).ok_or_else(|| {
                SiteError::new("AUTHORITY_ERROR", "member certificate serial exhausted")
            })?;
        }
        // The cutover stages through the shared GK allocator: a live P5
        // rotation's staged key is superseded (its operation closes as
        // such, its rows go) — the next GK only ever travels inside
        // PREPAREs, never as a P5 Update on the old network.
        let superseded_rotation = self.gks.rotation().map(|r| r.row.operation_id);
        let staged_delete: Vec<u32> = self.gks.staged_epoch().into_iter().collect();
        let state = CutoverState {
            phase: CutoverPhase::Preparing,
            old_network,
            new_network,
            expected_site_epoch: current_epoch,
            new_site_epoch: new_epoch,
            revision: 1,
            next_site_cert: request.next_site_cert.clone(),
            next_gk_epoch: staged_epoch,
            gk_owner_op: op_id,
            package_revision: self.revision,
            commit_rs_epoch: 0,
            commit_object: Vec::new(),
            commit_rrs: Vec::new(),
            carry: Vec::new(),
            started_mono_ms: time.mono_ms,
            commit_unix_ms: 0,
            targets,
        };
        let op = Operation {
            id: op_id,
            kind: "cutover".into(),
            node: 0,
            generation: 0,
            member_cert_serial: 0,
            rs_epoch: self.rs_epoch,
            gk_from: self.gks.active_epoch(),
            gk_to: staged_epoch,
            created_ms: now_ms,
            gk_cause: String::new(),
            gk_end: String::new(),
            distribution: None,
            cutover: Some(state),
            notice: None,
        };
        let result = format!(
            "{{\"operation_id\":\"{}\",\"state\":\"preparing\",\"expected_site_epoch\":{current_epoch},\"new_site_epoch\":{new_epoch},\"revision\":1,\"targets\":{}}}",
            op_token(op.id),
            members.len(),
        );
        let mut batch = Batch {
            meta: vec![
                ("next_serial", serial.to_be_bytes().to_vec()),
                (META_HIGH_WATER, staged_epoch.to_be_bytes().to_vec()),
            ],
            group_keys: vec![GroupKeyRow {
                epoch: staged_epoch,
                key: staged_key,
                state: "staged".into(),
                created_ms: now_ms,
            }],
            group_keys_delete: staged_delete,
            ..Batch::default()
        };
        if superseded_rotation.is_some() {
            batch.gk_rotation = RotationWrite::Delete;
            batch.gk_targets_clear = true;
        }
        if let Some(old) = superseded_rotation {
            if let Some(prior) = self.operations.get(&old).cloned() {
                let mut prior = prior;
                prior.gk_end = "superseded".into();
                batch
                    .docs
                    .push((DocKind::Operation, h16(prior.id), Some(prior.doc())));
            }
        }
        let evicted = self.operation_doc(&mut batch, &op)?;
        self.decision_doc(
            &mut batch,
            &principal,
            &request.key,
            digest,
            &result,
            now_ms,
        );
        if let Err(error) = self.store.commit(&batch) {
            self.store_error(now_ms, &error);
            return Err(store_failure(&error));
        }
        if let Some(old) = superseded_rotation {
            if let Some(prior) = self.operations.get_mut(&old) {
                prior.gk_end = "superseded".into();
            }
        }
        self.gks
            .publish_cutover_staging(staged_epoch, GkSecret::new(staged_key), now_ms);
        self.gk_outbox.clear();
        self.next_serial = serial;
        self.remember_operation(op.clone(), evicted);
        self.remember_decision(&principal, &request.key, digest, &result, now_ms);
        self.event(
            now_ms,
            format!(
                "\"kind\":\"cutover.progress\",\"operation_id\":\"{}\",\"phase\":\"preparing\",\"new_site_epoch\":{new_epoch},\"revision\":1,\"targets\":{}",
                op_token(op.id),
                members.len(),
            ),
        );
        Ok(result)
    }

    /// Assembles one target's PREPARE plaintext deterministically from
    /// the durable snapshot (04 §5.3): the head, the new network, both
    /// certificates, a zero-time SitePackage pinned to the cutover's
    /// revision, and the target's fresh DAMS. The same bytes re-verify
    /// a PREPARED digest after any restart.
    fn assemble_prepare(
        &self,
        op_id: u64,
        target: &CutoverTarget,
        state: &CutoverState,
    ) -> Option<Vec<u8>> {
        let key = self.key_for_epoch(state.next_gk_epoch)?;
        let package = SitePackage {
            site_id: self.id.site_id,
            network: state.new_network,
            rs_epoch: 0,
            gk_epoch: state.next_gk_epoch,
            gk: *key.bytes(),
            channel: self.id.channel,
            role: target.role,
            gateway_count: self.id.gateway_count,
            channel_epoch: self.id.channel_epoch,
            gateways: self.id.gateways,
            authority_time_s: 0,
            time_uncertainty_ms: 0,
            membership_revision: state.package_revision,
        };
        let package = package.encode().ok()?;
        let head = Head {
            phase: Phase::Prepare,
            cutover_id: op_id,
            revision: state.revision,
            old_network: state.old_network,
        };
        Prepare {
            head,
            new_network: state.new_network,
            site_cert: &state.next_site_cert,
            member_cert: &target.member_cert,
            site_package: &package,
            dams: target.dams,
        }
        .encode()
        .ok()
    }

    /// Assembles the COMMIT plaintext from the durable commit artifacts
    /// (04 §5.3): the head, the CutoverCommit proof and the next RRS1.
    fn assemble_commit(&self, op_id: u64, state: &CutoverState) -> Option<Vec<u8>> {
        let head = Head {
            phase: Phase::Commit,
            cutover_id: op_id,
            revision: state.revision,
            old_network: state.old_network,
        };
        Commit {
            head,
            proof: &state.commit_object,
            rrs: &state.commit_rrs,
        }
        .encode()
        .ok()
    }

    /// The distribution half of [`SiteAuthority::tick`] for cutovers:
    /// restarts a pre-commit window once after the reopen (the
    /// monotonic clock never survives it), queues due PREPAREs, commits
    /// at the lapse with a current-revision gateway PREPARED, then
    /// queues COMMITs inside the grace. Stragglers past the grace park
    /// in `recovery_pending` for the ZT reissue.
    pub(super) fn tick_cutover(&mut self, time: HostTime) {
        // Queueing rides the wall axis like the rest of the shared
        // outbox (dispatch, pacing and backoff all compare unix); only
        // the 600 s window and the 60 s grace run on the monotonic
        // axis below.
        self.queue_notices(time);
        if !self.cutover_resume_pending.is_empty() {
            let pending = std::mem::take(&mut self.cutover_resume_pending);
            self.restart_cutover_window(&pending, time.mono_ms);
        }
        let Some(id) = self.live_cutover() else {
            self.cutover_routes.clear();
            self.cutover_gk_proved.clear();
            return;
        };
        self.cutover_routes.retain(|(op, _), _| *op == id);
        self.cutover_gk_proved.retain(|(op, _), _| *op == id);
        let phase = self
            .operations
            .get(&id)
            .and_then(|op| op.cutover.as_ref())
            .map(|state| state.phase);
        match phase {
            Some(CutoverPhase::Preparing | CutoverPhase::WaitingGateway) => {
                self.queue_grants(id, OutboundKind::Prepare, time);
                // Late PREPARE learns the tree (04 §7): only Prepared
                // targets are worth asking, so early ticks queue
                // nothing and COMMIT dispatch rarely waits a round trip.
                self.queue_route_queries(id, time);
                let lapsed = self.operations.get(&id).and_then(|op| {
                    op.cutover.as_ref().map(|state| {
                        time.mono_ms
                            >= state
                                .started_mono_ms
                                .saturating_add(CUTOVER_PREPARE_WINDOW_MS)
                    })
                });
                if lapsed != Some(true) {
                    return;
                }
                if self.cutover_ready_to_commit(id) {
                    self.cutover_commit(id, time);
                } else if phase == Some(CutoverPhase::Preparing) {
                    self.set_cutover_phase(id, CutoverPhase::WaitingGateway, time.unix_ms);
                }
            }
            Some(CutoverPhase::Committed) => {
                let grace_over = self
                    .cutover_grace()
                    .is_none_or(|(_, until)| time.mono_ms > until);
                if !grace_over {
                    self.cutover_apply_layer_deadlines(id, time.mono_ms);
                    // A stored child may have left the old mesh. Ask
                    // remaining targets again before releasing their
                    // COMMITs, even while an older route lease lives.
                    self.queue_route_queries(id, time);
                    self.queue_grants(id, OutboundKind::Commit, time);
                }
                let terminal = self.operations.get(&id).and_then(|op| {
                    op.cutover.as_ref().map(|state| {
                        state.targets.iter().all(|t| {
                            matches!(
                                t.state,
                                GrantState::Applied | GrantState::Recovered | GrantState::Retired
                            )
                        })
                    })
                });
                if terminal == Some(true) {
                    self.set_cutover_phase(id, CutoverPhase::Converged, time.unix_ms);
                } else if grace_over {
                    self.set_cutover_phase(id, CutoverPhase::RecoveryPending, time.unix_ms);
                }
            }
            _ => {}
        }
    }

    /// True when the lapse may commit: every target list is empty (the
    /// degenerate no-member cutover) or a gateway PREPAREDed at the
    /// latest revision (04 §8.2: at least one, never stale).
    fn cutover_ready_to_commit(&self, id: u64) -> bool {
        match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) if state.targets.is_empty() => true,
            Some(state) => {
                let gateways = state
                    .targets
                    .iter()
                    .filter(|t| {
                        t.gateway
                            && t.state == GrantState::Prepared
                            && t.prepared_revision == state.revision
                    })
                    .count();
                gateways >= CUTOVER_GATEWAY_MIN
            }
            None => false,
        }
    }

    fn set_cutover_phase(&mut self, id: u64, phase: CutoverPhase, now_ms: u64) {
        let mut updated = match self.operations.get(&id).cloned() {
            Some(op) => op,
            None => return,
        };
        if let Some(state) = updated.cutover.as_mut() {
            if state.phase == phase {
                return;
            }
            state.phase = phase;
        }
        let batch = Batch {
            docs: vec![(DocKind::Operation, h16(updated.id), Some(updated.doc()))],
            ..Batch::default()
        };
        if let Err(error) = self.store.commit(&batch) {
            self.store_error(now_ms, &error);
            return;
        }
        self.operations.insert(id, updated);
        self.event(
            now_ms,
            format!(
                "\"kind\":\"cutover.progress\",\"operation_id\":\"{}\",\"phase\":\"{}\"",
                op_token(id),
                phase.name(),
            ),
        );
    }

    /// Restarts a reopened pre-commit window once: the monotonic
    /// start never survives the reopen (04 §8.2), so the 600 s count
    /// begins at the first tick. Only the cutovers collected at open
    /// restart — never one staged live in this boot. The serials, the
    /// staged key and the issued grants are reused: nothing new is
    /// consumed.
    fn restart_cutover_window(&mut self, pending: &[u64], now_mono_ms: u64) {
        for id in pending {
            let restart = self.operations.get(id).and_then(|op| {
                op.cutover.as_ref().map(|state| {
                    matches!(
                        state.phase,
                        CutoverPhase::Preparing | CutoverPhase::WaitingGateway
                    )
                })
            });
            if restart != Some(true) {
                continue;
            }
            let mut updated = match self.operations.get(id).cloned() {
                Some(op) => op,
                None => continue,
            };
            if let Some(state) = updated.cutover.as_mut() {
                state.started_mono_ms = now_mono_ms;
            }
            self.operations.insert(*id, updated);
            self.persist_operation(*id, now_mono_ms);
        }
    }

    /// The durable COMMIT's monotonic instant, recovered from the
    /// grace it opened (RAM-only like the grace: 0 means no grace).
    fn cutover_commit_t0(&self) -> u64 {
        self.cutover_grace_until_mono
            .saturating_sub(CUTOVER_GRACE_MS)
    }

    /// True once the member plan closed (T0 + 40 s): every unconfirmed
    /// non-gateway target is deferred then, and only the roots still
    /// move. D and this instant never move (04 §7).
    fn cutover_plan_closed(&self, now_mono: u64) -> bool {
        self.cutover_grace_until_mono == 0
            || now_mono
                >= self
                    .cutover_commit_t0()
                    .saturating_add(CUTOVER_GRACE_MS.saturating_sub(CUTOVER_GATEWAY_FLUSH_MS))
    }

    /// The leaf-first release gate for one COMMIT (04 §7): a member
    /// moves once its reporting subtree settled (stored, applied, or
    /// cut) and no unrelated target without a usable report is still
    /// unconfirmed — reports the gate cannot see serialize behind
    /// the report it waits for, never ahead of it. A gateway (root)
    /// moves once every non-gateway target settled, or once the plan
    /// closes; with no non-gateway target it moves at once. The
    /// latest-PREPARED and binding checks stay with the caller.
    fn commit_releasable(&self, id: u64, node: u64, now_mono: u64) -> bool {
        let Some(state) = self.operations.get(&id).and_then(|op| op.cutover.as_ref()) else {
            return false;
        };
        let Some(target) = state.targets.iter().find(|t| t.node == node) else {
            return false;
        };
        if matches!(
            target.state,
            GrantState::Applied | GrantState::Recovered | GrantState::Retired
        ) {
            return false;
        }
        // A layer-deadline cut ends the sends: the target fell back to
        // the ZT reissue, and retries would only burn the grace that
        // the remaining frontier still needs.
        if self
            .cutover_routes
            .get(&(id, node))
            .is_some_and(|plan| plan.deferred || plan.stored)
        {
            return false;
        }
        let settled = |t: &CutoverTarget| {
            t.state == GrantState::Retired
                || self
                    .cutover_routes
                    .get(&(id, t.node))
                    .is_some_and(|plan| plan.settled(t.state))
                || t.state == GrantState::Applied
                || t.state == GrantState::Recovered
        };
        if target.gateway {
            let out = self.cutover_plan_closed(now_mono)
                || state
                    .targets
                    .iter()
                    .filter(|t| !t.gateway && t.state != GrantState::Retired)
                    .all(settled);
            return out;
        }
        if self.cutover_plan_closed(now_mono) {
            return false;
        }
        let tree = route_tree(
            &state.targets,
            &self.cutover_routes,
            id,
            state.revision,
            now_mono,
        );
        let known = self
            .cutover_routes
            .get(&(id, node))
            .and_then(|plan| plan.usable(state.revision, now_mono))
            .is_some();
        // A cached plan invalidated by a child's adoption needs a new
        // answer before its first dispatch. Already-sent COMMITs may
        // continue their bounded retries.
        if self
            .cutover_routes
            .get(&(id, node))
            .is_some_and(|plan| plan.recheck_due)
            && !known
            && target.attempts == 0
        {
            return false;
        }
        let descendants = tree.descendants(node);
        let ancestors = tree.ancestors(node);
        !state.targets.iter().any(|t| {
            t.node != node
                && !t.gateway
                && t.state != GrantState::Retired
                && !settled(t)
                && (descendants.contains(&t.node)
                    || (known
                        && !ancestors.contains(&t.node)
                        && self
                            .cutover_routes
                            .get(&(id, t.node))
                            .and_then(|plan| plan.usable(state.revision, now_mono))
                            .is_none()))
        })
    }

    /// Cuts the layers whose frame lapsed (04 §7): the first 40 s
    /// split into H frames from the deepest layer, and every
    /// unconfirmed non-gateway target in a lapsed layer defers —
    /// including ones never tried. Settled targets never move back.
    fn cutover_apply_layer_deadlines(&mut self, id: u64, now_mono: u64) {
        let until = self.cutover_grace_until_mono;
        if until == 0 {
            return;
        }
        let t0 = until.saturating_sub(CUTOVER_GRACE_MS);
        let frames = CUTOVER_GRACE_MS.saturating_sub(CUTOVER_GATEWAY_FLUSH_MS);
        let state = match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) => state.clone(),
            None => return,
        };
        let tree = route_tree(
            &state.targets,
            &self.cutover_routes,
            id,
            state.revision,
            now_mono,
        );
        if tree.h == 0 {
            return;
        }
        for target in &state.targets {
            if target.gateway || matches!(target.state, GrantState::Retired | GrantState::Recovered)
            {
                continue;
            }
            if self
                .cutover_routes
                .get(&(id, target.node))
                .is_some_and(|plan| plan.settled(target.state))
                || target.state == GrantState::Applied
            {
                continue;
            }
            let layer = tree
                .depths
                .get(&target.node)
                .copied()
                .flatten()
                .unwrap_or(tree.h)
                .clamp(1, tree.h);
            let cutoff = t0
                .saturating_add(frames.saturating_mul((tree.h - layer + 1) as u64) / tree.h as u64);
            if now_mono >= cutoff {
                self.cutover_routes
                    .entry((id, target.node))
                    .or_default()
                    .deferred = true;
            }
        }
    }

    /// Queues due grant sends into the shared paced outbox (04 §9.1: at
    /// most 4 live mails, 10 objects/s, newest work first). Pre-commit
    /// only PREPAREs go out; post-commit only COMMITs — never a new
    /// PREPARE on the retired network (04 §8.5).
    fn queue_grants(&mut self, id: u64, kind: OutboundKind, time: HostTime) {
        if self
            .rrs_transport
            .as_ref()
            .is_none_or(|transport| !transport.carries_grant())
        {
            return;
        }
        let state = match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) => state.clone(),
            None => return,
        };
        let now_ms = time.unix_ms;
        for target in &state.targets {
            if self.rrs_outbox.len() >= DISTRIBUTION_OUTBOX_MAX {
                break;
            }
            match target.state {
                GrantState::Applied | GrantState::Recovered | GrantState::Retired => continue,
                GrantState::Prepared
                    if kind == OutboundKind::Prepare
                        && target.prepared_revision == state.revision =>
                {
                    continue;
                }
                _ => {}
            }
            // A COMMIT needs the latest PREPARED behind it: without a
            // staged intent the device would reject it, so the
            // unprepared stay unknown for the ZT reissue instead of
            // burning airtime. PREPARE needs no ordering: staging
            // never retires.
            if kind == OutboundKind::Commit {
                let releasable = target.state == GrantState::Prepared
                    && target.prepared_revision == state.revision
                    && self.commit_releasable(id, target.node, time.mono_ms);
                if !releasable {
                    continue;
                }
            }
            if matches!(target.state, GrantState::Unknown | GrantState::Prepared)
                && target.next_retry_ms > now_ms
            {
                continue;
            }
            if self
                .rrs_outbox
                .iter()
                .any(|o| o.op == id && o.node == target.node && o.what == kind)
            {
                continue;
            }
            if self
                .rrs_refusals
                .get(&(id, target.node, kind))
                .is_some_and(|(due, _)| *due > now_ms)
            {
                continue;
            }
            // The snapshot never drifts under the event loop
            // (revoke/allow fold their changes into their own
            // transactions); a drifted binding fails closed: no send.
            let live = self.devices.get(&target.node).filter(|row| {
                row.member && row.kid == target.kid && row.generation == target.generation
            });
            if live.is_none() {
                continue;
            }
            self.rrs_outbox.push_back(OutboundRrs {
                op: id,
                node: target.node,
                what: kind,
            });
        }
    }

    /// Queues RouteState queries for targets lacking a usable report
    /// (04 §7). PREPARE asks only in its last minute; after a child
    /// stores COMMIT, pending targets are asked again before dispatch.
    /// Only Prepared non-gateway targets need an uplink report.
    fn queue_route_queries(&mut self, id: u64, time: HostTime) {
        if self
            .rrs_transport
            .as_ref()
            .is_none_or(|transport| !transport.carries_grant())
        {
            return;
        }
        let state = match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) => state.clone(),
            None => return,
        };
        let late_prepare = state.phase == CutoverPhase::Preparing
            && time.mono_ms
                >= state
                    .started_mono_ms
                    .saturating_add(CUTOVER_PREPARE_WINDOW_MS)
                    .saturating_sub(CUTOVER_ROUTE_QUERY_WINDOW_MS);
        if state.phase != CutoverPhase::WaitingGateway
            && state.phase != CutoverPhase::Committed
            && !late_prepare
        {
            return;
        }
        let now_ms = time.unix_ms;
        for target in &state.targets {
            if self.rrs_outbox.len() >= DISTRIBUTION_OUTBOX_MAX {
                break;
            }
            if target.gateway {
                continue;
            }
            if !matches!(target.state, GrantState::Prepared)
                || target.prepared_revision != state.revision
            {
                continue;
            }
            if self
                .cutover_routes
                .get(&(id, target.node))
                .is_some_and(|plan| {
                    plan.deferred
                        || plan.stored
                        || plan.usable(state.revision, time.mono_ms).is_some()
                })
            {
                continue;
            }
            if self
                .rrs_outbox
                .iter()
                .any(|o| o.op == id && o.node == target.node && o.what == OutboundKind::RouteQuery)
            {
                continue;
            }
            if self
                .rrs_refusals
                .get(&(id, target.node, OutboundKind::RouteQuery))
                .is_some_and(|(due, _)| *due > now_ms)
            {
                continue;
            }
            let live = self.devices.get(&target.node).filter(|row| {
                row.member && row.kid == target.kid && row.generation == target.generation
            });
            if live.is_none() {
                continue;
            }
            self.rrs_outbox.push_back(OutboundRrs {
                op: id,
                node: target.node,
                what: OutboundKind::RouteQuery,
            });
        }
    }

    /// Dispatch-time recheck for a queued query: the answer may have
    /// landed while the mail lingered in the paced outbox.
    pub(super) fn route_query_still_due(&self, op: u64, node: u64, now_ms: u64) -> bool {
        let Some(state) = self.operations.get(&op).and_then(|o| o.cutover.as_ref()) else {
            return false;
        };
        if !matches!(
            state.phase,
            CutoverPhase::Preparing | CutoverPhase::WaitingGateway | CutoverPhase::Committed
        ) {
            return false;
        }
        let Some(target) = state.targets.iter().find(|t| t.node == node) else {
            return false;
        };
        if target.state != GrantState::Prepared || target.prepared_revision != state.revision {
            return false;
        }
        if self.cutover_routes.get(&(op, node)).is_some_and(|plan| {
            plan.deferred
                || plan.stored
                || plan
                    .usable(state.revision, self.last_channel_mono_ms)
                    .is_some()
        }) {
            return false;
        }
        if self
            .rrs_refusals
            .get(&(op, node, OutboundKind::RouteQuery))
            .is_some_and(|(due, _)| *due > now_ms)
        {
            return false;
        }
        self.devices.get(&node).is_some_and(|row| {
            row.member && row.kid == target.kid && row.generation == target.generation
        })
    }

    /// Assembles one RouteState query with a fresh id (never 0):
    /// the id becomes the outstanding one for this target, so a late
    /// answer to a superseded query never steers dispatch.
    pub(super) fn route_query_bytes(&mut self, op: u64, node: u64) -> Option<Vec<u8>> {
        let state = self.operations.get(&op).and_then(|o| o.cutover.as_ref())?;
        let head = Head {
            phase: Phase::RouteState,
            cutover_id: op,
            revision: state.revision,
            old_network: state.old_network,
        };
        let mut seq = self.cutover_query_seq.wrapping_add(1);
        if seq == 0 {
            seq = ROUTE_QUERY_FIRST_ID;
        }
        self.cutover_query_seq = seq;
        self.cutover_routes.entry((op, node)).or_default().query_id = seq;
        RouteState {
            head,
            mode: 0,
            status: 0,
            root: 0,
            parent: 0,
            boot: 0,
            route_stamp: 0,
            query_id: seq,
            valid_for_ms: 0,
        }
        .encode()
        .ok()
        .map(|bytes| bytes.to_vec())
    }

    /// Records a query send: unanswered rounds back off on the shared
    /// ladder (an answer resets the round and clears the wait). The
    /// grant retry of the target never moves. A pending re-query
    /// holds COMMIT until its own route report arrives.
    pub(super) fn note_route_query_sent(&mut self, op: u64, node: u64, now_ms: u64) {
        let plan = self.cutover_routes.entry((op, node)).or_default();
        plan.query_attempts = plan.query_attempts.saturating_add(1);
        let wait = DISTRIBUTION_BACKOFF_S
            [(plan.query_attempts as usize - 1).min(DISTRIBUTION_BACKOFF_S.len() - 1)]
        .saturating_mul(1000);
        self.rrs_refusals.insert(
            (op, node, OutboundKind::RouteQuery),
            (now_ms.saturating_add(wait), 1),
        );
    }

    /// Records a grant send: attempts advance with the shared bounded
    /// backoff (5/10/20/40/60 s, capped); a first send moves Pending to
    /// Unknown. Receipts — never sends — move targets to Prepared and
    /// Applied.
    pub(super) fn note_grant_sent(&mut self, op: u64, node: u64, now_ms: u64) {
        let Some(operation) = self.operations.get_mut(&op) else {
            return;
        };
        let Some(state) = operation.cutover.as_mut() else {
            return;
        };
        for target in state.targets.iter_mut() {
            if target.node != node {
                continue;
            }
            if matches!(
                target.state,
                GrantState::Applied | GrantState::Recovered | GrantState::Retired
            ) {
                continue;
            }
            if target.state == GrantState::Pending {
                target.state = GrantState::Unknown;
            }
            target.attempts = target.attempts.saturating_add(1);
            let wait = DISTRIBUTION_BACKOFF_S
                [(target.attempts as usize - 1).min(DISTRIBUTION_BACKOFF_S.len() - 1)]
            .saturating_mul(1000);
            target.next_retry_ms = now_ms.saturating_add(wait);
        }
    }

    /// Re-arms `device`'s due grants on a (re)opened channel: the
    /// retry and refusal deadlines drop to now, so the next tick
    /// queues the grant immediately instead of at a backoff deadline
    /// the fresh channel may not live to see (a COMMIT cadence that
    /// keeps missing every Ready window stalls past the 60 s grace
    /// otherwise). RAM-only like all backoff timers: no persist.
    pub(super) fn rearm_grants_for_channel(&mut self, device: u64, now_ms: u64) {
        let ids: Vec<u64> = self.operations.keys().copied().collect();
        for id in ids {
            let mut rearmed = false;
            if let Some(state) = self
                .operations
                .get_mut(&id)
                .and_then(|op| op.cutover.as_mut())
            {
                for target in state.targets.iter_mut() {
                    if target.node != device {
                        continue;
                    }
                    if matches!(
                        target.state,
                        GrantState::Applied | GrantState::Recovered | GrantState::Retired
                    ) {
                        continue;
                    }
                    if target.next_retry_ms > now_ms {
                        target.next_retry_ms = now_ms;
                        rearmed = true;
                    }
                }
            }
            if rearmed {
                // A pending refusal would gate the re-queue past the
                // window the fresh channel just opened. The release
                // gate still applies — the rearm hurries, never
                // bypasses.
                self.rrs_refusals
                    .remove(&(id, device, OutboundKind::Prepare));
                self.rrs_refusals
                    .remove(&(id, device, OutboundKind::Commit));
                self.rrs_refusals
                    .remove(&(id, device, OutboundKind::RouteQuery));
            }
        }
    }

    /// True while the queued grant still wants airtime (the dispatch
    /// drops converged, retired and meanwhile-acked entries silently).
    pub(super) fn grant_still_due(
        &self,
        op: u64,
        node: u64,
        kind: OutboundKind,
        now_ms: u64,
    ) -> bool {
        match self.operations.get(&op).and_then(|o| o.cutover.as_ref()) {
            Some(state) => state.targets.iter().any(|t| {
                if t.node != node {
                    return false;
                }
                match t.state {
                    GrantState::Applied | GrantState::Recovered | GrantState::Retired => false,
                    GrantState::Prepared
                        if kind == OutboundKind::Prepare
                            && t.prepared_revision == state.revision =>
                    {
                        false
                    }
                    GrantState::Unknown | GrantState::Prepared if t.next_retry_ms > now_ms => false,
                    _ => {
                        // The frontier re-checks at dispatch: a mail
                        // that lingered in the paced outbox must not
                        // jump the queue the tree refined meanwhile.
                        // `last_channel_mono_ms` is this tick's clock
                        // (set before both drain paths run).
                        kind != OutboundKind::Commit
                            || (t.state == GrantState::Prepared
                                && t.prepared_revision == state.revision
                                && self.commit_releasable(op, node, self.last_channel_mono_ms))
                    }
                }
            }),
            None => false,
        }
    }

    /// Resolves one queued grant to its plaintext bytes. PREPAREs are
    /// reassembled from the durable snapshot; the COMMIT comes from the
    /// durable commit artifacts — never from RAM that a restart lost.
    pub(super) fn grant_bytes(&self, op: u64, node: u64, kind: OutboundKind) -> Option<Vec<u8>> {
        let state = self.operations.get(&op).and_then(|o| o.cutover.as_ref())?;
        match kind {
            OutboundKind::Prepare => {
                if !matches!(
                    state.phase,
                    CutoverPhase::Preparing | CutoverPhase::WaitingGateway
                ) {
                    return None;
                }
                let target = state.targets.iter().find(|t| t.node == node)?;
                self.assemble_prepare(op, target, state)
            }
            OutboundKind::Commit => {
                if state.phase != CutoverPhase::Committed {
                    return None;
                }
                if !state.targets.iter().any(|t| {
                    t.node == node
                        && !matches!(
                            t.state,
                            GrantState::Applied | GrantState::Recovered | GrantState::Retired
                        )
                }) {
                    return None;
                }
                self.assemble_commit(op, state)
            }
            _ => None,
        }
    }

    /// The commit transaction (04 §8.2): the live assignments are
    /// re-verified, then the next RRS1, the CutoverCommit, the active
    /// SiteCert/network/GK/DAMS/MemberCerts, the retired old network
    /// and the operation land in one SQLite transaction. No COMMIT is
    /// ever sent before it. Any mismatch fails closed — the cutover
    /// stays pre-commit and the next tick retries — and never partly.
    fn cutover_commit(&mut self, id: u64, time: HostTime) {
        let now_ms = time.unix_ms;
        let op = match self.operations.get(&id).cloned() {
            Some(op) => op,
            None => return,
        };
        let state = match op.cutover.clone() {
            Some(state)
                if matches!(
                    state.phase,
                    CutoverPhase::Preparing | CutoverPhase::WaitingGateway
                ) =>
            {
                state
            }
            _ => return,
        };
        if self.gks.rotation().is_some() {
            self.event(
                now_ms,
                "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"a group rotation is live\"".to_string(),
            );
            return;
        }
        // Every non-retired target must still be exactly the staged
        // binding; revoke/allow keep the snapshot current, so a miss
        // means tampering or a bug — never commit past it.
        for target in &state.targets {
            if target.state == GrantState::Retired {
                continue;
            }
            let live = self.devices.get(&target.node).filter(|row| {
                row.member && row.kid == target.kid && row.generation == target.generation
            });
            if live.is_none() {
                self.event(
                    now_ms,
                    "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"snapshot drift\"".to_string(),
                );
                return;
            }
        }
        let commit_rs = match checked_next(self.rs_epoch, "rs_epoch") {
            Ok(epoch) => epoch,
            Err(error) => {
                self.event(
                    now_ms,
                    format!(
                        "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"{}\"",
                        error.message
                    ),
                );
                return;
            }
        };
        let next_revision = match checked_next(self.revision, "membership revision") {
            Ok(revision) => revision,
            Err(error) => {
                self.event(
                    now_ms,
                    format!(
                        "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"{}\"",
                        error.message
                    ),
                );
                return;
            }
        };
        // The staged key must be exactly the cutover's, strictly above
        // every epoch the old network ever published (04 §8.3).
        let staged_key = self.gks.staged_key().cloned();
        if self.gks.staged_epoch() != Some(state.next_gk_epoch)
            || state.next_gk_epoch <= self.gks.active_epoch()
            || staged_key.is_none()
        {
            self.event(
                now_ms,
                "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"staged key mismatch\"".to_string(),
            );
            return;
        }
        let staged_key = staged_key.expect("staged key checked");
        let Some(ca) = self.id.site_ca_pubkey else {
            self.event(
                now_ms,
                "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"site CA missing\"".to_string(),
            );
            return;
        };
        let next_claims = match cert_verify(&state.next_site_cert, &ca) {
            Ok((claims, true)) => claims,
            _ => {
                self.event(
                    now_ms,
                    "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"next SiteCert rejected\"".to_string(),
                );
                return;
            }
        };
        let mut carry = state.carry.clone();
        carry.sort_by_key(|e| e.node_id);
        let set = RevocationSet {
            site_id: self.id.site_id,
            network: state.new_network,
            rs_epoch: commit_rs,
            site_epoch_floor: state.new_site_epoch,
            entries: carry.clone(),
        };
        let rrs = match revocation_issue(&set, self.sak.as_ref()) {
            Ok(object) => object,
            Err(error) => {
                self.event(
                    now_ms,
                    format!(
                        "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"next RRS1 issue failed: {error}\""
                    ),
                );
                return;
            }
        };
        let proof = CutoverCommit {
            site_id: self.id.site_id,
            old_network: state.old_network,
            new_network: state.new_network,
            cutover_id: id,
            revision: state.revision,
            gk_epoch: state.next_gk_epoch,
            rs_epoch: commit_rs,
            rrs_sha256: sha256(&rrs),
        };
        let commit_object = match proof.issue(self.sak.as_ref()) {
            Ok(object) => object,
            Err(error) => {
                self.event(
                    now_ms,
                    format!(
                        "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"CutoverCommit issue failed: {error}\""
                    ),
                );
                return;
            }
        };
        // The member rows switch to their staged grants: the next cert
        // (same bytes the device PREPAREd), the next DAMS. Confirms
        // restart on the new network.
        let mut devices = Vec::new();
        for target in &state.targets {
            if target.state == GrantState::Retired {
                continue;
            }
            let mut row = match self.devices.get(&target.node).cloned() {
                Some(row) => row,
                None => continue,
            };
            row.member_cert = target.member_cert.clone();
            row.member_cert_serial = target.member_cert_serial;
            row.dams = target.dams;
            row.confirmed = false;
            row.confirmed_ms = None;
            devices.push(row);
        }
        let ledger = self.ledger_row("cutover", 0, [0; 32], 0, sha256(&commit_object), now_ms);
        let Some(mut epochs) = self.store_epoch_timeline() else {
            self.event(
                now_ms,
                "\"kind\":\"authority.error\",\"reason\":\"cutover_commit\",\"detail\":\"cutover timeline unavailable\"".to_string(),
            );
            return;
        };
        epochs.extend_from_slice(&commit_rs.to_be_bytes());
        epochs.extend_from_slice(&state.new_network.to_be_bytes());
        let mut binding = self.id.site_id.to_be_bytes().to_vec();
        binding.extend_from_slice(&state.new_network.to_be_bytes());
        binding.extend_from_slice(&self.id.sak_kid);
        let mut updated = op.clone();
        if let Some(next) = updated.cutover.as_mut() {
            next.phase = CutoverPhase::Committed;
            // PREPARE backoff is not a COMMIT attempt: let the first
            // post-commit send through immediately, then pace retries.
            for target in &mut next.targets {
                if target.state == GrantState::Prepared {
                    target.attempts = 0;
                    target.next_retry_ms = 0;
                }
            }
            next.commit_rs_epoch = commit_rs;
            next.commit_object = commit_object.clone();
            next.commit_rrs = rrs.clone();
            next.commit_unix_ms = now_ms;
        }
        // The commit RRS distributes like a revoke's set: every grant
        // target owes an Applied receipt on the new network — the
        // straggler's reissue ACK is what `rrs_ok` reads to mark its
        // recovery (04 §7).
        {
            let mut targets: Vec<DistributionTarget> = state
                .targets
                .iter()
                .filter(|t| t.state != GrantState::Retired)
                .take(DISTRIBUTION_TARGET_MAX)
                .map(|t| DistributionTarget {
                    node: t.node,
                    kid: t.kid,
                    generation: t.generation,
                    network: state.new_network,
                    state: RrsTargetState::Pending,
                    attempts: 0,
                    next_retry_ms: 0,
                    ack_rs_epoch: None,
                })
                .collect();
            targets.sort_by_key(|t| t.node);
            let overflow = state
                .targets
                .iter()
                .filter(|t| t.state != GrantState::Retired)
                .count()
                .saturating_sub(DISTRIBUTION_TARGET_MAX) as u32;
            updated.distribution = Some(OperationDistribution {
                state: DistState::Pending,
                rs_epoch: commit_rs,
                network: state.new_network,
                object_sha256: sha256(&rrs),
                targets,
                overflow,
            });
        }
        let active_epoch = self.gks.active_epoch();
        let retired_notices: Vec<Operation> = self
            .operations
            .values()
            .filter_map(|operation| {
                let mut updated = operation.clone();
                let notice = updated.notice.as_mut()?;
                if notice.network != state.old_network
                    || notice.delivery != super::revocation::NoticeDelivery::Pending
                {
                    return None;
                }
                notice.delivery = super::revocation::NoticeDelivery::Unreachable;
                Some(updated)
            })
            .collect();
        let mut batch = Batch {
            devices,
            ledger: vec![ledger.clone()],
            rrs: vec![(commit_rs, rrs.clone())],
            meta: vec![
                ("rs_epoch", commit_rs.to_be_bytes().to_vec()),
                ("revision", next_revision.to_be_bytes().to_vec()),
                (
                    super::group_keys::META_ACTIVATED_MS,
                    now_ms.to_be_bytes().to_vec(),
                ),
                (META_ACTIVE_SITE_CERT, state.next_site_cert.clone()),
                (META_CUTOVER_EPOCHS, epochs),
                ("site_binding", binding),
            ],
            group_keys: vec![GroupKeyRow {
                epoch: state.next_gk_epoch,
                key: *staged_key.bytes(),
                state: "active".into(),
                created_ms: self.gks.staged_created_ms(),
            }],
            group_keys_delete: vec![active_epoch],
            docs: vec![(DocKind::Operation, h16(updated.id), Some(updated.doc()))],
            ..Batch::default()
        };
        for operation in &retired_notices {
            batch
                .docs
                .push((DocKind::Operation, h16(operation.id), Some(operation.doc())));
        }
        if let Err(error) = self.store.commit(&batch) {
            self.store_error(now_ms, &error);
            return;
        }
        // Committed: the RAM model follows, then the old network gets
        // its 60 s of COMMIT grace.
        self.ledger_seq = ledger.seq;
        self.ledger_head = ledger.hash;
        self.revision = next_revision;
        self.rs_epoch = commit_rs;
        self.rrs_entries = carry.clone();
        self.rrs_history.insert(commit_rs, carry);
        self.rrs_history_digests.insert(commit_rs, sha256(&rrs));
        self.rrs_latest_object = rrs;
        for row in batch.devices.clone() {
            self.devices.insert(row.node, row);
        }
        self.gks.publish_cutover_activation(now_ms, time.mono_ms);
        self.id.network = state.new_network;
        self.id.site_cert = state.next_site_cert.clone();
        self.id.site_claims = next_claims;
        self.cutover_grace_network = state.old_network;
        self.cutover_grace_until_mono = time.mono_ms.saturating_add(CUTOVER_GRACE_MS);
        self.operations.insert(id, updated);
        for operation in retired_notices {
            self.operations.insert(operation.id, operation);
        }
        // The port keeps serving the old network for the COMMIT grace
        // (RAM-only, like `cutover_grace_until_mono` above); fakes and
        // the transport-less state ignore the note.
        if let Some(transport) = self.rrs_transport.as_mut() {
            transport.note_p6_cutover(state.old_network, time.mono_ms);
        }
        self.prune_rrs_history();
        let (prepared, applied, recovered, unknown, _) = self
            .operations
            .get(&id)
            .and_then(|op| op.cutover.as_ref())
            .map(|s| s.counts())
            .unwrap_or((0, 0, 0, 0, 0));
        self.event(
            now_ms,
            format!(
                "\"kind\":\"cutover.progress\",\"operation_id\":\"{}\",\"phase\":\"committed\",\"new_site_epoch\":{},\"revision\":{},\"rs_epoch\":{commit_rs},\"gk_epoch\":{},\"prepared\":{prepared},\"applied\":{applied},\"recovered\":{recovered},\"unknown\":{unknown}",
                op_token(id),
                state.new_site_epoch,
                state.revision,
                state.next_gk_epoch,
            ),
        );
    }

    /// The durable epoch timeline (`META_CUTOVER_EPOCHS`), empty before
    /// the first commit. A torn timeline fails the commit, never a
    /// silent fork.
    fn store_epoch_timeline(&mut self) -> Option<Vec<u8>> {
        let snapshot = self.store.load().ok()?;
        let bytes = snapshot
            .meta
            .get(META_CUTOVER_EPOCHS)
            .cloned()
            .unwrap_or_default();
        parse_cutover_epochs(&bytes)?;
        Some(bytes)
    }

    /// Records a GrantRenew receipt from a device (called by the P5
    /// authority channel with the context-bound node/generation/
    /// network). PREPARED counts pre-commit only, at the latest
    /// revision, with the exact PREPARE digest; APPLIED counts
    /// post-commit only, over the new context — or over the old
    /// context inside the COMMIT grace (04 §7) — with the exact
    /// COMMIT digest. Anything else is ignored. Returns true when a
    /// target moved.
    pub fn handle_grant_receipt(
        &mut self,
        node: u64,
        generation: u32,
        network: u64,
        receipt: &[u8],
        time: HostTime,
    ) -> bool {
        let now_ms = time.unix_ms;
        let receipt = match Receipt::decode(receipt) {
            Ok(receipt) => receipt,
            Err(_) => {
                return false;
            }
        };
        let id = receipt.head.cutover_id;
        let state = match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) => state.clone(),
            None => {
                return false;
            }
        };
        if receipt.head.old_network != state.old_network
            || receipt.new_network != state.new_network
            || receipt.head.revision != state.revision
            || receipt.status != 0
        {
            return false;
        }
        // The binding is the live row's — a reassigned key never
        // inherits the old target's evidence.
        let live = match self.devices.get(&node) {
            Some(row) if row.member && row.generation == generation => row.clone(),
            _ => {
                return false;
            }
        };
        let target = match state.targets.iter().find(|t| t.node == node) {
            Some(target) if target.generation == generation && target.kid == live.kid => {
                target.clone()
            }
            _ => {
                return false;
            }
        };
        if matches!(
            target.state,
            GrantState::Applied | GrantState::Recovered | GrantState::Retired
        ) {
            return false;
        }
        match receipt.head.phase {
            Phase::Prepared => {
                if !matches!(
                    state.phase,
                    CutoverPhase::Preparing | CutoverPhase::WaitingGateway
                ) || self.live_cutover() != Some(id)
                    || network != state.old_network
                    || receipt.gk_epoch != state.next_gk_epoch
                {
                    return false;
                }
                let Some(expect) = self.assemble_prepare(id, &target, &state) else {
                    return false;
                };
                if receipt.digest != sha256(&expect) {
                    return false;
                }
                if target.state == GrantState::Prepared
                    && target.prepared_revision == state.revision
                {
                    return false;
                }
                self.set_grant_state(id, node, GrantState::Prepared, state.revision, now_ms)
            }
            Phase::Applied => {
                // 04 §7: the device adopts over its old channel and
                // reports before any new-context channel exists, so an
                // authenticated old-context APPLIED counts inside the
                // COMMIT grace. The grace is the receive instant
                // against the RAM deadline — never the phase alone,
                // which can lag a tick (or a failed write-back) past
                // D — and it ends at D sharp, on restart (RAM), and
                // on clock regression (ended with the table flip).
                let until = self.cutover_grace_until_mono;
                let grace_applied = network == state.old_network
                    && state.phase == CutoverPhase::Committed
                    && until != 0
                    && time.mono_ms < until;
                if !matches!(
                    state.phase,
                    CutoverPhase::Committed
                        | CutoverPhase::RecoveryPending
                        | CutoverPhase::Converged
                ) || self.id.network != state.new_network
                    || !(network == state.new_network || grace_applied)
                    || receipt.rs_epoch != state.commit_rs_epoch
                    || receipt.gk_epoch != state.next_gk_epoch
                {
                    return false;
                }
                if receipt.digest != sha256(&state.commit_object) {
                    return false;
                }
                self.set_grant_state(id, node, GrantState::Applied, state.revision, now_ms)
            }
            // COMMIT_STORED and RouteState ride their own handlers
            // (leaf-first dispatch); never PREPARED/APPLIED evidence.
            Phase::Prepare | Phase::Commit | Phase::CommitStored | Phase::RouteState => false,
        }
    }

    /// Validates a COMMIT_STORED receipt (04 §7): the same
    /// cutover/revision the Host committed, the same COMMIT digest,
    /// epochs and networks, status 0, over the live old binding while
    /// the grace still covers the receive instant. Ordering only —
    /// the target's GrantState never moves here. True when the plan
    /// recorded it (duplicates re-record idempotently).
    pub(super) fn handle_commit_stored(
        &mut self,
        node: u64,
        generation: u32,
        network: u64,
        body: &[u8],
        mono_ms: u64,
    ) -> bool {
        let receipt = match Receipt::decode(body) {
            Ok(receipt) if receipt.head.phase == Phase::CommitStored => receipt,
            _ => return false,
        };
        let id = receipt.head.cutover_id;
        let state = match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) => state.clone(),
            None => return false,
        };
        if state.phase != CutoverPhase::Committed
            || receipt.head.revision != state.revision
            || receipt.head.old_network != state.old_network
            || network != state.old_network
            || receipt.new_network != state.new_network
            || receipt.status != 0
        {
            return false;
        }
        let until = self.cutover_grace_until_mono;
        if until == 0 || mono_ms >= until {
            return false;
        }
        let Some(target) = state.targets.iter().find(|t| t.node == node) else {
            return false;
        };
        let live = self
            .devices
            .get(&node)
            .is_some_and(|row| row.member && row.generation == generation && row.kid == target.kid);
        if !live || generation != target.generation {
            return false;
        }
        if receipt.rs_epoch != state.commit_rs_epoch
            || receipt.gk_epoch != state.next_gk_epoch
            || receipt.digest != sha256(&state.commit_object)
        {
            return false;
        }
        let plan = self.cutover_routes.entry((id, node)).or_default();
        if !plan.stored {
            plan.stored = true;
            // A child can adopt immediately after this receipt. Cached
            // parent leases of pending targets cannot authorize the
            // next COMMIT without a new, bound RouteState answer.
            for pending in state
                .targets
                .iter()
                .filter(|t| !t.gateway && t.node != node && t.attempts == 0)
            {
                let route = self.cutover_routes.entry((id, pending.node)).or_default();
                if route.stored || route.deferred || route.report.is_none() {
                    continue;
                }
                route.report = None;
                route.recheck_due = true;
                route.query_id = 0;
                route.query_attempts = 0;
                self.rrs_refusals
                    .remove(&(id, pending.node, OutboundKind::RouteQuery));
            }
        }
        true
    }

    /// Adopts a RouteState report (04 §7): the live cutover's binding
    /// plus the outstanding query id, over the live old binding
    /// (pre-commit, or post-commit while the grace covers the receive
    /// instant). Anything else — a superseded query, a foreign
    /// cutover, a dead binding — never steers dispatch. True when
    /// the plan adopted it.
    pub(super) fn handle_route_report(
        &mut self,
        node: u64,
        generation: u32,
        network: u64,
        body: &[u8],
        mono_ms: u64,
    ) -> bool {
        let report = match RouteState::decode(body) {
            Ok(report) if report.mode == 1 => report,
            _ => return false,
        };
        let id = report.head.cutover_id;
        let state = match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) => state.clone(),
            None => return false,
        };
        if !matches!(
            state.phase,
            CutoverPhase::Preparing | CutoverPhase::WaitingGateway | CutoverPhase::Committed
        ) || report.head.revision != state.revision
            || report.head.old_network != state.old_network
            || network != state.old_network
        {
            return false;
        }
        if state.phase == CutoverPhase::Committed {
            let until = self.cutover_grace_until_mono;
            if until == 0 || mono_ms >= until {
                return false;
            }
        }
        let Some(target) = state.targets.iter().find(|t| t.node == node) else {
            return false;
        };
        if matches!(
            target.state,
            GrantState::Applied | GrantState::Recovered | GrantState::Retired
        ) {
            return false;
        }
        let live = self
            .devices
            .get(&node)
            .is_some_and(|row| row.member && row.generation == generation && row.kid == target.kid);
        if !live || generation != target.generation {
            return false;
        }
        let plan = self.cutover_routes.entry((id, node)).or_default();
        if plan.query_id == 0 || report.query_id != plan.query_id {
            return false;
        }
        plan.report = Some(RouteReport {
            root: report.root,
            parent: report.parent,
            boot: report.boot,
            stamp: report.route_stamp,
            query_id: report.query_id,
            lease_ms: report.valid_for_ms,
            revision: state.revision,
            recv_mono_ms: mono_ms,
            unavailable: report.status == 1,
        });
        if report.status == 0 {
            plan.recheck_due = false;
        }
        plan.query_attempts = 0;
        self.rrs_refusals
            .remove(&(id, node, OutboundKind::RouteQuery));
        true
    }

    /// Moves one grant target, durably: the store commits before the
    /// RAM model follows (a failed write-back reports nothing). A
    /// fully-evidenced snapshot converges with its event.
    fn set_grant_state(
        &mut self,
        id: u64,
        node: u64,
        state: GrantState,
        revision: u32,
        now_ms: u64,
    ) -> bool {
        let mut updated = match self.operations.get(&id).cloned() {
            Some(op) => op,
            None => return false,
        };
        let converged = match updated.cutover.as_mut() {
            Some(cutover) => {
                let mut moved = false;
                for target in cutover.targets.iter_mut() {
                    if target.node != node {
                        continue;
                    }
                    if matches!(
                        target.state,
                        GrantState::Applied | GrantState::Recovered | GrantState::Retired
                    ) {
                        continue;
                    }
                    target.state = state;
                    target.prepared_revision = revision;
                    moved = true;
                }
                if !moved {
                    return false;
                }
                cutover.targets.iter().all(|t| {
                    matches!(
                        t.state,
                        GrantState::Applied | GrantState::Recovered | GrantState::Retired
                    )
                })
            }
            None => return false,
        };
        if converged {
            if let Some(cutover) = updated.cutover.as_mut() {
                cutover.phase = CutoverPhase::Converged;
            }
        }
        let batch = Batch {
            docs: vec![(DocKind::Operation, h16(updated.id), Some(updated.doc()))],
            ..Batch::default()
        };
        match self.store.commit(&batch) {
            Ok(()) => {
                self.operations.insert(id, updated);
                if converged {
                    self.event(
                        now_ms,
                        format!(
                            "\"kind\":\"cutover.progress\",\"operation_id\":\"{}\",\"phase\":\"converged\"",
                            op_token(id)
                        ),
                    );
                }
                true
            }
            Err(error) => {
                self.store_error(now_ms, &error);
                false
            }
        }
    }

    /// Records that `node` verifiably holds GK `epoch` (04 §7): the
    /// caller checked the gk_id (ACK) or the fenced JoinConfirm view.
    /// RAM-only evidence for the Recovered transition below.
    pub(super) fn note_cutover_gk_proved(&mut self, node: u64, epoch: u32) {
        if epoch == 0 {
            return;
        }
        if let Some(id) = self.live_cutover() {
            self.cutover_gk_proved.insert((id, node), epoch);
        }
    }

    /// Marks a cutover target Recovered once its ZT reissue fully
    /// evidenced (04 §7): a verified JoinConfirm on the live row (the
    /// generation/cert/DAMS binding the target snapshot shares), the
    /// committed RRS Applied on the new network, and the current GK
    /// proven. Only unknown (Pending/Unknown/Prepared) targets of a
    /// post-commit cutover move; Applied/Retired/Recovered never do.
    /// The move is durable (store first) like every grant transition.
    /// True when the target moved.
    pub(super) fn cutover_maybe_recover(&mut self, node: u64, now_ms: u64) -> bool {
        let Some(id) = self.live_cutover() else {
            return false;
        };
        let state = match self.operations.get(&id).and_then(|op| op.cutover.as_ref()) {
            Some(state) => state.clone(),
            None => return false,
        };
        // Converged needs no arm: all its targets are terminal, so no
        // unknown target can exist to recover.
        if !matches!(
            state.phase,
            CutoverPhase::Committed | CutoverPhase::RecoveryPending
        ) {
            return false;
        }
        let target = match state.targets.iter().find(|t| t.node == node) {
            Some(target)
                if matches!(
                    target.state,
                    GrantState::Pending | GrantState::Unknown | GrantState::Prepared
                ) =>
            {
                target.clone()
            }
            _ => return false,
        };
        if !self.devices.get(&node).is_some_and(|row| {
            row.member
                && row.confirmed
                && row.generation == target.generation
                && row.kid == target.kid
        }) {
            return false;
        }
        // The RRS the cutover committed (or a newer set): an Applied
        // ack on the new network for this binding. Anything older is
        // not the recovery evidence.
        let rrs_ok = self.operations.values().any(|op| {
            op.distribution.as_ref().is_some_and(|dist| {
                dist.network == state.new_network
                    && dist.targets.iter().any(|t| {
                        t.node == node
                            && t.network == state.new_network
                            && t.generation == target.generation
                            && t.kid == target.kid
                            && t.state == RrsTargetState::Applied
                            && t.ack_rs_epoch.is_some_and(|e| e >= state.commit_rs_epoch)
                    })
            })
        });
        if !rrs_ok {
            return false;
        }
        let active = self.gks.active_epoch();
        if active == 0 || self.cutover_gk_proved.get(&(id, node)) != Some(&active) {
            return false;
        }
        if !self.set_grant_state(id, node, GrantState::Recovered, state.revision, now_ms) {
            return false;
        }
        self.event(
            now_ms,
            format!(
                "\"kind\":\"cutover.recovered\",\"operation_id\":\"{}\",\"device_id\":\"{}\"",
                op_token(id),
                h16(node)
            ),
        );
        true
    }

    /// Previews an allow folded into a live pre-commit cutover (04
    /// §8.3): the newcomer — or the reassigned binding — joins the
    /// snapshot with a fresh next MemberCert and DAMS. Pure: the caller
    /// folds the returned operation into its own commit and publishes
    /// it only after. A full snapshot refuses instead of truncating.
    /// The revision and the window are untouched: a binding that never
    /// held the staged key cannot leak it.
    pub(super) fn cutover_join_preview(
        &self,
        row: &DeviceRow,
        next_cert: Vec<u8>,
        next_serial: u32,
    ) -> Result<Option<Operation>, SiteError> {
        let Some(id) = self.live_cutover() else {
            return Ok(None);
        };
        let mut updated = match self.operations.get(&id).cloned() {
            Some(op) => op,
            None => return Ok(None),
        };
        let pre_commit = updated.cutover.as_ref().is_some_and(|state| {
            matches!(
                state.phase,
                CutoverPhase::Preparing | CutoverPhase::WaitingGateway
            )
        });
        if !pre_commit {
            return Ok(None);
        }
        let joined = match updated.cutover.as_mut() {
            Some(state) => {
                if !state.targets.iter().any(|t| t.node == row.node)
                    && state.targets.len() >= CUTOVER_TARGET_MAX
                {
                    return Err(SiteError::new(
                        "NO_CAPACITY",
                        "the live cutover snapshot is full; the cutover must commit first",
                    )
                    .retry());
                }
                let dams = fresh_secret()?;
                let gateway =
                    self.id.gateways[..usize::from(self.id.gateway_count)].contains(&row.node);
                match state.targets.iter_mut().find(|t| t.node == row.node) {
                    Some(target) => {
                        // A reassignment: the new binding restarts
                        // unprepared; the old PREPARED is void.
                        target.kid = row.kid;
                        target.generation = row.generation;
                        target.role = row.role;
                        target.gateway = gateway;
                        target.member_cert = next_cert;
                        target.member_cert_serial = next_serial;
                        target.dams = dams;
                        target.state = GrantState::Pending;
                        target.prepared_revision = 0;
                        target.attempts = 0;
                        target.next_retry_ms = 0;
                    }
                    None => state.targets.push(CutoverTarget {
                        node: row.node,
                        kid: row.kid,
                        generation: row.generation,
                        role: row.role,
                        gateway,
                        member_cert: next_cert,
                        member_cert_serial: next_serial,
                        dams,
                        state: GrantState::Pending,
                        prepared_revision: 0,
                        attempts: 0,
                        next_retry_ms: 0,
                    }),
                }
                state.targets.sort_by_key(|t| t.node);
                true
            }
            None => false,
        };
        Ok(joined.then_some(updated))
    }

    /// Previews a revoke folded into the live cutover (04 §8.3).
    /// Pre-commit, the issued-then-removed binding is carried into the
    /// next RRS1, the target retires, the next GK is re-staged under a
    /// new revision, every PREPARED is voided and the window restarts;
    /// post-commit the target just retires. Pure: the caller folds the
    /// effect into its own commit and publishes it only after. A carry
    /// set past 32 refuses before anything commits — the live cutover
    /// must land first, then the same generation retries on the new
    /// network.
    pub(super) fn cutover_revoke_preview(
        &self,
        removed_node: u64,
        removed_generation: u32,
        reason: RevocationReason,
        revoke_op: u64,
        now_mono_ms: u64,
    ) -> Result<RevokeCutoverEffect, SiteError> {
        let active = self.gks.active_epoch();
        let Some(id) = self.live_cutover() else {
            return Ok(RevokeCutoverEffect::none(active));
        };
        let pre_commit = self
            .operations
            .get(&id)
            .and_then(|op| op.cutover.as_ref())
            .is_some_and(|state| {
                matches!(
                    state.phase,
                    CutoverPhase::Preparing | CutoverPhase::WaitingGateway
                )
            });
        if !pre_commit {
            // Post-commit revokes are plain new-network revokes; the
            // target just owes no grant anymore.
            return Ok(RevokeCutoverEffect {
                updated: self.cutover_retire_preview(removed_node),
                superseded_owner: None,
                staged: None,
                delete_staged: Vec::new(),
                gk_epochs: (active, active),
                revision: None,
            });
        }
        let mut updated = match self.operations.get(&id).cloned() {
            Some(op) => op,
            None => return Ok(RevokeCutoverEffect::none(active)),
        };
        // ACK or not, an issued grant is assumed known (04 §8.3): the
        // removed binding is carried unless it never held one.
        let had_grant = updated.cutover.as_ref().is_some_and(|state| {
            state.targets.iter().any(|t| {
                t.node == removed_node
                    && t.generation == removed_generation
                    && !matches!(t.state, GrantState::Retired)
            })
        });
        if had_grant {
            let min_generation = removed_generation.checked_add(1).ok_or_else(|| {
                SiteError::new("AUTHORITY_ERROR", "assignment generation exhausted")
            })?;
            let carry_len = updated
                .cutover
                .as_ref()
                .map(|state| {
                    state
                        .carry
                        .iter()
                        .filter(|e| e.node_id != removed_node)
                        .count()
                })
                .unwrap_or(0);
            if carry_len >= REVOCATION_ENTRY_MAX {
                return Err(SiteError::new(
                    "NO_CAPACITY",
                    "the live cutover's next revocation set is full; retry after it commits",
                )
                .retry());
            }
            if let Some(state) = updated.cutover.as_mut() {
                state.carry.retain(|e| e.node_id != removed_node);
                state.carry.push(RevocationEntry {
                    node_id: removed_node,
                    min_generation,
                    reason,
                });
                state.carry.sort_by_key(|e| e.node_id);
            }
        }
        // The staged key the removed member may hold is replaced; the
        // revision moves and every PREPARED voids with it.
        let staged_epoch = self
            .gks
            .next_epoch()
            .map_err(|message| SiteError::new("AUTHORITY_ERROR", message))?;
        let staged_key =
            fresh_group_key().map_err(|message| SiteError::new("AUTHORITY_ERROR", message))?;
        if staged_key.iter().all(|v| *v == 0) {
            return Err(SiteError::new(
                "AUTHORITY_ERROR",
                "staged group key is zero; entropy failure",
            ));
        }
        let revision = match updated.cutover.as_ref() {
            Some(state) => checked_next(state.revision, "cutover revision")?,
            None => return Ok(RevokeCutoverEffect::none(active)),
        };
        let delete_staged: Vec<u32> = self.gks.staged_epoch().into_iter().collect();
        let previous_owner = updated.cutover.as_ref().map(|state| state.gk_owner_op);
        if let Some(state) = updated.cutover.as_mut() {
            state.next_gk_epoch = staged_epoch;
            state.gk_owner_op = revoke_op;
            state.revision = revision;
            state.started_mono_ms = now_mono_ms;
            for target in state.targets.iter_mut() {
                if target.node == removed_node {
                    target.state = GrantState::Retired;
                } else if target.state == GrantState::Prepared {
                    target.state = GrantState::Unknown;
                }
                target.prepared_revision = 0;
                if target.state == GrantState::Unknown {
                    target.next_retry_ms = 0;
                }
            }
        }
        updated.gk_to = staged_epoch;
        let superseded_owner = match previous_owner {
            Some(owner) if owner != id => self.operations.get(&owner).cloned().map(|mut prior| {
                prior.gk_end = "superseded".into();
                prior
            }),
            _ => None,
        };
        Ok(RevokeCutoverEffect {
            updated: Some(updated),
            superseded_owner,
            staged: Some((staged_epoch, staged_key)),
            delete_staged,
            gk_epochs: (active, staged_epoch),
            revision: Some(revision),
        })
    }

    /// Publishes a committed revoke-cutover effect to RAM (only after
    /// the commit): the cutover snapshot, the superseded owner, the
    /// re-staged key — and the revision event KGuard watches.
    pub(super) fn publish_revoke_cutover(&mut self, effect: RevokeCutoverEffect, now_ms: u64) {
        let mut restaged = None;
        if let Some(updated) = effect.updated {
            restaged = updated
                .cutover
                .as_ref()
                .map(|state| (updated.id, state.revision));
            self.operations.insert(updated.id, updated);
        }
        if let Some((id, _)) = restaged {
            self.rrs_refusals.retain(|(op, _, kind), _| {
                *op != id
                    || !matches!(
                        kind,
                        OutboundKind::Prepare | OutboundKind::Commit | OutboundKind::RouteQuery
                    )
            });
        }
        if let Some(prior) = effect.superseded_owner {
            self.operations.insert(prior.id, prior);
        }
        if let Some((epoch, key)) = effect.staged {
            self.gks
                .publish_cutover_staging(epoch, GkSecret::new(key), now_ms);
            self.gk_outbox.clear();
        }
        if let (Some((id, _)), Some(revision)) = (restaged, effect.revision) {
            self.event(
                now_ms,
                format!(
                    "\"kind\":\"cutover.progress\",\"operation_id\":\"{id}\",\"phase\":\"preparing\",\"revision\":{revision},\"restaged\":true",
                ),
            );
        }
    }

    /// Previews `node` retired from the live cutover snapshot (a
    /// post-commit revoke removed it: no grant is owed anymore). Pure:
    /// the caller folds the returned operation into its own commit.
    fn cutover_retire_preview(&self, node: u64) -> Option<Operation> {
        let id = self.live_cutover()?;
        let mut updated = self.operations.get(&id).cloned()?;
        let mut changed = false;
        if let Some(state) = updated.cutover.as_mut() {
            for target in state.targets.iter_mut() {
                if target.node == node
                    && !matches!(target.state, GrantState::Applied | GrantState::Retired)
                {
                    target.state = GrantState::Retired;
                    changed = true;
                }
            }
        }
        changed.then_some(updated)
    }

    /// The `operations.get` body for a cutover (07 §2.2): the phase,
    /// both epochs, the revision, the grant counts, the gateway and
    /// recovery flags and the window remainder (monotonic; display
    /// only — the tick decides on the same clock).
    pub(super) fn cutover_view(&self, op: &Operation, now: HostTime) -> Option<String> {
        let state = op.cutover.as_ref()?;
        let (prepared, applied, recovered, unknown, total) = state.counts();
        let waiting_gateway = state.phase == CutoverPhase::WaitingGateway;
        let recovery_pending = state.phase == CutoverPhase::RecoveryPending;
        let deadline = match state.phase {
            CutoverPhase::Preparing | CutoverPhase::WaitingGateway => state
                .started_mono_ms
                .saturating_add(CUTOVER_PREPARE_WINDOW_MS)
                .saturating_sub(now.mono_ms)
                .to_string(),
            _ => "null".to_string(),
        };
        Some(format!(
            "{{\"operation_id\":\"{}\",\"kind\":\"cutover\",\"phase\":\"{}\",\"expected_site_epoch\":{},\"new_site_epoch\":{},\"revision\":{},\"prepared\":{prepared},\"applied\":{applied},\"recovered\":{recovered},\"unknown\":{unknown},\"total\":{total},\"waiting_gateway\":{waiting_gateway},\"recovery_pending\":{recovery_pending},\"deadline_remaining_ms\":{deadline},\"commit_rs_epoch\":{},\"created_ms\":{}}}",
            op_token(op.id),
            state.phase.name(),
            state.expected_site_epoch,
            state.new_site_epoch,
            state.revision,
            state.commit_rs_epoch,
            op.created_ms
        ))
    }
}
