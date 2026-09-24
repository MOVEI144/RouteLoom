//! Host group-key lifecycle (G-SEC P5, design §6): the single RAM owner of
//! GK state inside [`SiteAuthority`](super::SiteAuthority) — the active and
//! staged keys, the epoch high-water mark, the one live rotation and its
//! member targets.
//!
//! Durable state (the `group_keys`, `gk_rotation` and `gk_targets` tables
//! plus three `meta` keys) always leads: every staging, activation,
//! convergence and ACK record commits to the store first, and the RAM
//! mirror below is published only after the commit. A commit failure
//! changes nothing and queues nothing.
//!
//! The rotation FSM (`Stable → Staging → Activating → CatchingUp →
//! Stable`) runs on [`HostTime`]: monotonic milliseconds for staging
//! deadlines, send retries and rate limiting, wall milliseconds for audit
//! timestamps and the post-restart 24 h residual. A restart never extends
//! an old deadline: a persisted staging rotation resumes as expired (it
//! activates at the first tick), and a rotation that is merely due starts
//! exactly once.
//!
//! Commands leave through [`GroupKeyTransport`], the seam PR1's authority
//! channel implements (PR4 wires it to USB). Delivery is best-effort: only
//! a durable device ACK (`result == 0`) is convergence evidence, never a
//! queued or sent command.

use std::collections::BTreeMap;

use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::fill_random;
use zeroize::Zeroize;

use super::records::ROLE_GATEWAY;
use super::store::{DeviceRow, GroupKeyRow};

/// Live members (gateways included) a rotation can target. The 129th allow
/// is refused before commit; an over-capacity migrated database refuses new
/// rotations without truncating the target list (design §6.1).
pub const MEMBER_CAP: usize = 128;
/// Fixed rotation period (v1 has no 1–168 h knob, §6.2).
pub const GK_ROTATION_PERIOD_MS: u64 = 24 * 3600 * 1000;
/// Staging deadline of a periodic or manual rotation.
pub const GK_STAGE_DEADLINE_PERIODIC_MS: u64 = 60_000;
/// Staging deadline of a removal rotation.
pub const GK_STAGE_DEADLINE_REMOVAL_MS: u64 = 30_000;
/// After an activation, further periodic/manual rotations wait out this
/// cleanup window; only a revocation supersedes (§6.3).
pub const GK_CLEANUP_MS: u64 = 60_000;
/// Distribution rate: new business commands per second, with burst.
pub const GK_SENDS_PER_SEC: u64 = 10;
pub const GK_SEND_BURST: u64 = 4;
/// Sends per contact before a target goes unknown (then a 1 min round).
pub const GK_MAX_ATTEMPTS: u32 = 4;
/// Retry gaps after send 1/2/3; the 4th send exhausts the round (§6.2).
pub const GK_RETRY_DELAYS_MS: [u64; 3] = [2_000, 4_000, 8_000];
/// An unknown target is retried every minute until it converges.
pub const GK_UNKNOWN_RETRY_MS: u64 = 60_000;
/// A Wake hint is re-sent at most this often per target.
pub const GK_WAKE_RETRY_MS: u64 = 2_000;
/// Bounded handoff to the transport (§2.2: full means "try next tick",
/// never dropped state or ACKs).
pub const GK_OUTBOX_CAP: usize = 32;
/// `meta` keys of §6.1 alongside the `group_keys` rows.
pub const META_HIGH_WATER: &str = "gk_epoch_high_water";
pub const META_ACTIVATED_MS: &str = "gk_activated_ms";
pub const META_LAST_ROTATION: &str = "gk_last_rotation";

/// The two clocks of §6.2, injected together so tests drive both axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostTime {
    /// Process-monotonic milliseconds: staging deadlines, retries, rate.
    pub mono_ms: u64,
    /// Wall milliseconds: audit timestamps, the 24 h residual after boot.
    pub unix_ms: u64,
}

impl HostTime {
    /// Both axes pinned together (unit tests without clock skew).
    pub fn sync(ms: u64) -> Self {
        Self {
            mono_ms: ms,
            unix_ms: ms,
        }
    }
}

/// Why a rotation started. Discriminants are the §3.1 wire `cause` values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RotationCause {
    Periodic = 1,
    Removal = 2,
    Manual = 3,
}

impl RotationCause {
    pub fn name(self) -> &'static str {
        match self {
            Self::Periodic => "periodic",
            Self::Removal => "removal",
            Self::Manual => "manual",
        }
    }

    pub fn parse(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Periodic,
            2 => Self::Removal,
            3 => Self::Manual,
            _ => return None,
        })
    }

    /// The only overlap each cause may carry (§3.1: not a generic timeout).
    pub fn overlap_s(self) -> u16 {
        match self {
            Self::Periodic | Self::Manual => 60,
            Self::Removal => 10,
        }
    }

    pub fn stage_deadline_ms(self) -> u64 {
        match self {
            Self::Periodic | Self::Manual => GK_STAGE_DEADLINE_PERIODIC_MS,
            Self::Removal => GK_STAGE_DEADLINE_REMOVAL_MS,
        }
    }
}

/// Phase of the live rotation (`Stable` is the absence of one).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationPhase {
    /// The staged key is being distributed; ends at full staged-ACK or at
    /// the deadline, never on silence alone.
    Staging,
    /// The new key is active in the database; first Activate round running.
    Activating,
    /// First Activate round done; stragglers stay honestly unknown without
    /// blocking the next 24 h rotation.
    CatchingUp,
}

impl RotationPhase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Activating => "activating",
            Self::CatchingUp => "catching_up",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "staging" => Self::Staging,
            "activating" => Self::Activating,
            "catching_up" => Self::CatchingUp,
            _ => return None,
        })
    }
}

/// Durable evidence a target produced for the live rotation's epoch.
/// `Unknown` keeps no evidence: the next round restarts at Update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetState {
    Pending,
    StagedAcked,
    ActiveAcked,
    Unknown,
}

impl TargetState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::StagedAcked => "staged_acked",
            Self::ActiveAcked => "active_acked",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pending" => Self::Pending,
            "staged_acked" => Self::StagedAcked,
            "active_acked" => Self::ActiveAcked,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

/// A group key held in RAM. Deliberately without `Debug`/`Display`/
/// `Serialize`: it is wiped on drop and on every retirement path, and must
/// never reach events, the API or the USB diagnostics (§9).
#[derive(Clone)]
pub struct GkSecret([u8; 32]);

impl Zeroize for GkSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for GkSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GkSecret {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `GK-id` of §3.1: the ACK-matching identifier (not a key export).
/// `SHA256("RouteLoom/v1/gk-id" || 0x00 || network:u64 || epoch:u32 || GK)`.
pub fn gk_id(network: u64, epoch: u32, key: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(16 + 1 + 8 + 4 + 32);
    input.extend_from_slice(b"RouteLoom/v1/gk-id");
    input.push(0x00);
    input.extend_from_slice(&network.to_be_bytes());
    input.extend_from_slice(&epoch.to_be_bytes());
    input.extend_from_slice(key);
    sha256(&input)
}

/// A fresh nonzero group key: at most four RNG draws (§6.1 forbids the old
/// unbounded `while`).
pub fn fresh_group_key() -> Result<[u8; 32], String> {
    let mut key = [0_u8; 32];
    for _ in 0..4 {
        fill_random(&mut key).map_err(|e| format!("group key entropy: {e}"))?;
        if key.iter().any(|&b| b != 0) {
            return Ok(key);
        }
    }
    Err("group key entropy failed four draws".into())
}

/// One GK command for a member, queued by the rotation FSM and sent on the
/// authority channel (PR1/PR4). Field order follows the §3.1 bodies.
pub enum GroupKeyCommand {
    /// Type 2 op 1 (stage): full key, only ever to a live member.
    Update {
        node: u64,
        epoch: u32,
        key: GkSecret,
        cause: RotationCause,
        overlap_s: u16,
    },
    /// Type 3 op 1: key identifier, never the key itself.
    Activate {
        node: u64,
        epoch: u32,
        gk_id: [u8; 32],
        cause: RotationCause,
        overlap_s: u16,
    },
    /// A rate-limited "the host needs a channel" hint (§3.2 kind 5); it
    /// carries no key, generation or floor and changes no state.
    Wake { node: u64 },
}

impl GroupKeyCommand {
    pub fn node(&self) -> u64 {
        match self {
            Self::Update { node, .. } | Self::Activate { node, .. } | Self::Wake { node } => *node,
        }
    }
}

// Redacted on purpose: a `{:?}` of a queued command must stay log-safe.
impl std::fmt::Debug for GroupKeyCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Update {
                node,
                epoch,
                cause,
                overlap_s,
                ..
            } => f
                .debug_struct("Update")
                .field("node", &format_args!("{node:016x}"))
                .field("epoch", epoch)
                .field("cause", &cause.name())
                .field("overlap_s", overlap_s)
                .field("key", &"<redacted>")
                .finish(),
            Self::Activate {
                node,
                epoch,
                cause,
                overlap_s,
                ..
            } => f
                .debug_struct("Activate")
                .field("node", &format_args!("{node:016x}"))
                .field("epoch", epoch)
                .field("cause", &cause.name())
                .field("overlap_s", overlap_s)
                .field("gk_id", &"<redacted>")
                .finish(),
            Self::Wake { node } => f
                .debug_struct("Wake")
                .field("node", &format_args!("{node:016x}"))
                .finish(),
        }
    }
}

/// Sends GK commands on the authority channel (design §6.2; the transport
/// trait PR1 implements). `channel_ready` runs under the authority lock, so
/// it must be a fast non-blocking read — implementations must never call
/// back into the authority while holding their channel table. `send` runs
/// with the lock released (the `SiteService::with` discipline) and is
/// best-effort: a queued command is never reach evidence.
pub trait GroupKeyTransport: Send + Sync {
    /// True when an established authority channel to `node` can carry a
    /// command right now (PR1's channel table; tests use a fake set).
    fn channel_ready(&self, node: u64) -> bool;
    /// Best-effort send of one queued command.
    fn send(&self, command: GroupKeyCommand);
}

/// A type 2/3 op-2 ACK as the channel layer hands it to the authority: the
/// channel-authenticated identity plus the envelope body fields (§3.1).
/// The `dams` copy is the incarnation fence (§4/§6.3), memory-only.
pub struct GroupKeyAck {
    pub node: u64,
    pub kid: [u8; 32],
    pub generation: u32,
    pub dams: [u8; 32],
    /// The ACK body: epoch, GK-id, result, stored state.
    pub epoch: u32,
    pub gk_id: [u8; 32],
    /// 0 = durable (the only convergence evidence), 1 = conflict, 2 =
    /// storage failure, 3 = busy, 4 = unsupported.
    pub result: u8,
    /// 0 = unapplied, 1 = staged, 2 = active.
    pub stored_state: u8,
}

impl std::fmt::Debug for GroupKeyAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupKeyAck")
            .field("node", &format_args!("{:016x}", self.node))
            .field("generation", &self.generation)
            .field("epoch", &self.epoch)
            .field("result", &self.result)
            .field("stored_state", &self.stored_state)
            .field("kid", &"<redacted>")
            .field("dams", &"<redacted>")
            .field("gk_id", &"<redacted>")
            .finish()
    }
}

/// A type 4 op-1 pull as the channel layer hands it to the authority.
/// Pulls are never ACKed; they are answered with Update→Activate (§3.1).
pub struct GroupKeyPull {
    pub node: u64,
    pub kid: [u8; 32],
    pub generation: u32,
    pub dams: [u8; 32],
    /// The device's `max(current, next)` is compared against the host
    /// active/staged/high-water (§6.3).
    pub current: u32,
    /// 0 when the device holds no staged next key.
    pub next: u32,
    /// 1 = unknown newer epoch, 2 = boot/reconnect sync, 3 = lost ACK/repair.
    pub reason: u8,
}

impl std::fmt::Debug for GroupKeyPull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupKeyPull")
            .field("node", &format_args!("{:016x}", self.node))
            .field("generation", &self.generation)
            .field("current", &self.current)
            .field("next", &self.next)
            .field("reason", &self.reason)
            .field("kid", &"<redacted>")
            .field("dams", &"<redacted>")
            .finish()
    }
}

/// What an ACK did (for tests and the PR1 channel mapping).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckOutcome {
    StagedRecorded,
    ActiveRecorded,
    /// A valid but already-recorded report; no state moved.
    Duplicate,
    /// Failed the membership/DAMS/epoch/GK-id fence (§9); `reason` feeds
    /// the `gk_rejected` counter.
    Stale {
        reason: &'static str,
    },
}

/// What a pull did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PullOutcome {
    /// Update→Activate queued (or the target marked due); the pull itself
    /// is never ACKed.
    Answered,
    Rejected {
        reason: &'static str,
    },
}

/// Typed `member_confirmed` result (§3.1): "already confirmed" and "store
/// failure" need distinct handling by the JoinConfirm responder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmOutcome {
    Confirmed,
    /// A duplicate JoinConfirm: ACK as the saved fact it is.
    AlreadyConfirmed,
    UnknownDevice,
    /// Stale generation/cert/DAMS or not a member: never ACK.
    Stale,
    StoreFailure,
}

/// The persisted `gk_rotation` row: at most one exists (§6.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationRow {
    pub operation_id: u64,
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub cause: RotationCause,
    pub phase: RotationPhase,
    pub members_revision: u32,
    pub created_ms: u64,
    /// Wall activation time, 0 until the Activating commit.
    pub activated_ms: u64,
}

/// The persisted `gk_targets` row: one per member of the live rotation.
/// The key itself is never copied here; the live member row is re-checked
/// at every send and every ACK (the incarnation fence needs no snapshot).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetRow {
    pub rotation: u64,
    pub node: u64,
    pub kid: [u8; 32],
    pub generation: u32,
    pub state: TargetState,
    pub confirmed_epoch: u32,
    pub confirmed_gkid: Option<[u8; 32]>,
    pub last_contact_ms: Option<u64>,
}

impl TargetRow {
    pub fn fresh(rotation: u64, node: u64, kid: [u8; 32], generation: u32) -> Self {
        Self {
            rotation,
            node,
            kid,
            generation,
            state: TargetState::Pending,
            confirmed_epoch: 0,
            confirmed_gkid: None,
            last_contact_ms: None,
        }
    }
}

/// The validated `group_keys` table: at most one active row, at most one
/// staged row above it, no zero keys, no unknown states.
pub struct ValidatedKeys {
    pub active_epoch: u32,
    pub active_key: [u8; 32],
    pub active_created_ms: u64,
    pub staged: Option<(u32, [u8; 32])>,
    pub high_water: u32,
}

/// Shared by the schema migration and `SiteAuthority::open` (§6.1): a
/// corrupt key table refuses to start rather than re-initialising over a
/// ledger that references it. Only a completely fresh database (no rows
/// anywhere) may mint epoch 1.
pub fn validate_group_keys(rows: &[GroupKeyRow], fresh: bool) -> Result<ValidatedKeys, String> {
    let mut active: Option<&GroupKeyRow> = None;
    let mut staged: Option<&GroupKeyRow> = None;
    for row in rows {
        if row.epoch == 0 || row.key.iter().all(|&b| b == 0) {
            return Err(format!(
                "site store group_keys epoch {} has a zero epoch or zero key",
                row.epoch
            ));
        }
        match row.state.as_str() {
            "active" => {
                if active.is_some() {
                    return Err("site store group_keys holds two active keys".into());
                }
                active = Some(row);
            }
            "staged" => {
                if staged.is_some() {
                    return Err("site store group_keys holds two staged keys".into());
                }
                staged = Some(row);
            }
            state => return Err(format!("site store group_keys has state {state:?}")),
        }
    }
    let Some(active) = active else {
        if fresh {
            return Err("fresh database without an active key (caller mints epoch 1)".into());
        }
        return Err(
            "site store has member state but no active group key (refusing to re-initialise)"
                .into(),
        );
    };
    if let Some(staged) = staged {
        if staged.epoch <= active.epoch {
            return Err(format!(
                "site store staged epoch {} is not above active {}",
                staged.epoch, active.epoch
            ));
        }
    }
    Ok(ValidatedKeys {
        active_epoch: active.epoch,
        active_key: active.key,
        active_created_ms: active.created_ms,
        staged: staged.map(|s| (s.epoch, s.key)),
        high_water: staged.map_or(active.epoch, |s| s.epoch),
    })
}

/// Encodes `meta.gk_last_rotation`: from:u32 | to:u32 | cause:u8 | pad:u8 |
/// reserved:u16 | activated_ms:u64 (BE, 20 B).
pub fn encode_last_rotation(
    from: u32,
    to: u32,
    cause: RotationCause,
    activated_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&from.to_be_bytes());
    out.extend_from_slice(&to.to_be_bytes());
    out.push(cause as u8);
    out.extend_from_slice(&[0; 3]);
    out.extend_from_slice(&activated_ms.to_be_bytes());
    out
}

pub fn decode_last_rotation(bytes: &[u8]) -> Option<(u32, u32, RotationCause, u64)> {
    if bytes.len() != 20 || bytes[9..12] != [0, 0, 0] {
        return None;
    }
    Some((
        u32::from_be_bytes(bytes[0..4].try_into().ok()?),
        u32::from_be_bytes(bytes[4..8].try_into().ok()?),
        RotationCause::parse(bytes[8])?,
        u64::from_be_bytes(bytes[12..20].try_into().ok()?),
    ))
}

/// The last converged rotation, for `group_keys.status` (meta mirror).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastRotation {
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub cause: RotationCause,
    pub activated_ms: u64,
}

/// A live rotation: the persisted [`RotationRow`] plus its RAM-only staging
/// deadline (monotonic, never restored across restarts — a resumed staging
/// rotation activates as expired instead, §6.2).
#[derive(Clone, Debug)]
pub struct LiveRotation {
    pub row: RotationRow,
    pub deadline_mono: u64,
}

/// A rotation target: the persisted [`TargetRow`] plus its RAM-only retry
/// progress (attempts and due time reset on restart; evidence never does).
#[derive(Clone, Debug)]
pub struct GkTarget {
    pub row: TargetRow,
    /// Sends of the current command kind (0 after exhaustion + backoff).
    pub attempts: u32,
    pub next_due_mono: u64,
    /// An Activate went out at least once (Activating→CatchingUp edge).
    pub activate_sent: bool,
    /// A pull showed this member behind the host active key: tick sends
    /// Update(active) before Update(to), and only stages after the active
    /// ACK (§6.3). Lost on restart; the member re-pulls, and a jumped
    /// Update(to) still converges it.
    pub active_first: bool,
}

impl GkTarget {
    pub fn fresh(row: TargetRow) -> Self {
        Self {
            row,
            attempts: 0,
            next_due_mono: 0,
            activate_sent: false,
            active_first: false,
        }
    }
}

/// What the tick sends a due target (after the channel check picks between
/// the command and a Wake hint).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GkSend {
    Update { epoch: u32 },
    Activate { epoch: u32 },
}

/// Edge the tick or an ACK found after recording evidence (the
/// staging→activation edge is [`GroupRotation::staging_finished`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationEdge {
    /// First Activate round done with stragglers left: persist the phase.
    ToCatchingUp,
    /// Every target active-ACKed: delete the rotation, close the operation.
    Converged,
}

/// Everything `SiteAuthority::open` hands the RAM mirror to restore.
pub struct RestoredState {
    pub active_epoch: u32,
    pub active_key: [u8; 32],
    pub staged: Option<(u32, [u8; 32], u64)>,
    pub high_water: u32,
    pub activated_ms: u64,
    pub last: Option<LastRotation>,
    pub rotation: Option<RotationRow>,
    pub targets: Vec<TargetRow>,
}

/// A staging commit, fully assembled before anything commits: fresh epoch
/// above the high-water mark, fresh key, full target set, supersede marks.
pub struct StagedPlan {
    pub op_id: u64,
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub key: [u8; 32],
    pub deadline_mono: u64,
    pub rotation_row: RotationRow,
    pub targets: Vec<TargetRow>,
    /// Staged rows the new key replaces (at most one).
    pub delete_epochs: Vec<u32>,
    /// Live rotation this one supersedes, if any.
    pub superseded_op: Option<u64>,
}

/// The single RAM owner of GK state (§2.1/§6.1). Retry progress, the rate
/// bucket and deadlines are RAM-only; everything else mirrors a committed
/// store row and is published only after the commit.
pub struct GroupRotation {
    active_epoch: u32,
    active_key: GkSecret,
    staged: Option<(u32, GkSecret)>,
    /// Wall creation time of the staged key (kept on the flipped row).
    staged_created_ms: u64,
    high_water: u32,
    /// Wall activation time of the active key (the 24 h anchor).
    activated_ms: u64,
    last: Option<LastRotation>,
    rotation: Option<LiveRotation>,
    targets: BTreeMap<u64, GkTarget>,
    bucket_units: u64,
    bucket_last_mono: u64,
    cleanup_until_mono: u64,
    overcap_warned: bool,
}

impl GroupRotation {
    pub fn new(
        active_epoch: u32,
        active_key: [u8; 32],
        high_water: u32,
        activated_ms: u64,
        last: Option<LastRotation>,
    ) -> Self {
        Self {
            active_epoch,
            active_key: GkSecret::new(active_key),
            staged: None,
            staged_created_ms: 0,
            high_water,
            activated_ms,
            last,
            rotation: None,
            targets: BTreeMap::new(),
            bucket_units: GK_SEND_BURST * 1000,
            bucket_last_mono: 0,
            cleanup_until_mono: 0,
            overcap_warned: false,
        }
    }

    /// Rebuilds the RAM mirror from committed rows (open / restart). Retry
    /// progress restarts; evidence never does. A persisted staging rotation
    /// resumes with an expired deadline (first tick activates); a resumed
    /// activating/catching-up rotation gets a fresh cleanup window at the
    /// first tick instead of a restored one.
    pub fn restore(state: RestoredState) -> Self {
        let mut gks = Self::new(
            state.active_epoch,
            state.active_key,
            state.high_water,
            state.activated_ms,
            state.last,
        );
        if let Some((epoch, key, created_ms)) = state.staged {
            gks.staged = Some((epoch, GkSecret::new(key)));
            gks.staged_created_ms = created_ms;
        }
        if let Some(row) = state.rotation {
            gks.rotation = Some(LiveRotation {
                row,
                deadline_mono: 0,
            });
            for target in state.targets {
                gks.targets.insert(target.node, GkTarget::fresh(target));
            }
        }
        gks
    }

    pub fn active_epoch(&self) -> u32 {
        self.active_epoch
    }

    pub fn active_key(&self) -> &GkSecret {
        &self.active_key
    }

    pub fn staged_epoch(&self) -> Option<u32> {
        self.staged.as_ref().map(|(epoch, _)| *epoch)
    }

    pub fn staged_key(&self) -> Option<&GkSecret> {
        self.staged.as_ref().map(|(_, key)| key)
    }

    pub fn staged_created_ms(&self) -> u64 {
        self.staged_created_ms
    }

    pub fn high_water(&self) -> u32 {
        self.high_water
    }

    pub fn activated_ms(&self) -> u64 {
        self.activated_ms
    }

    pub fn last_rotation(&self) -> Option<LastRotation> {
        self.last
    }

    pub fn rotation(&self) -> Option<&LiveRotation> {
        self.rotation.as_ref()
    }

    pub fn targets(&self) -> &BTreeMap<u64, GkTarget> {
        &self.targets
    }

    pub fn target(&self, node: u64) -> Option<&GkTarget> {
        self.targets.get(&node)
    }

    pub fn target_mut(&mut self, node: u64) -> Option<&mut GkTarget> {
        self.targets.get_mut(&node)
    }

    /// The next epoch, strictly above every epoch ever issued (§6.1: keys
    /// rows may be deleted, the high-water mark never moves back).
    pub fn next_epoch(&self) -> Result<u32, String> {
        self.high_water.checked_add(1).ok_or_else(|| {
            "group key epoch exhausted (u32::MAX issued); operator recovery required".into()
        })
    }

    /// True while a staging/activating rotation owns the single rotation
    /// slot; catching_up no longer blocks a successor (§6.3).
    pub fn rotation_in_progress(&self) -> bool {
        matches!(
            self.rotation.as_ref().map(|r| r.row.phase),
            Some(RotationPhase::Staging | RotationPhase::Activating)
        )
    }

    pub fn cleanup_active(&self, mono_ms: u64) -> bool {
        mono_ms < self.cleanup_until_mono
    }

    /// One token of the 10/s + burst-4 bucket (§6.2); integer math only.
    pub fn take_token(&mut self, mono_ms: u64) -> bool {
        const UNITS_PER_TOKEN: u64 = 1000;
        const UNITS_PER_MS: u64 = GK_SENDS_PER_SEC * UNITS_PER_TOKEN / 1000;
        let elapsed = mono_ms.saturating_sub(self.bucket_last_mono);
        self.bucket_last_mono = mono_ms;
        self.bucket_units = (self.bucket_units + elapsed.saturating_mul(UNITS_PER_MS))
            .min(GK_SEND_BURST * UNITS_PER_TOKEN);
        if self.bucket_units >= UNITS_PER_TOKEN {
            self.bucket_units -= UNITS_PER_TOKEN;
            true
        } else {
            false
        }
    }

    /// Due targets, gateways first (§6.2: Activates reach gateways first;
    /// the same order keeps Updates uniform), then by node id.
    pub fn due_targets(&self, mono_ms: u64, devices: &BTreeMap<u64, DeviceRow>) -> Vec<u64> {
        let mut due: Vec<u64> = self
            .targets
            .values()
            .filter(|t| t.next_due_mono <= mono_ms && t.row.state != TargetState::ActiveAcked)
            .map(|t| t.row.node)
            .collect();
        due.sort_by_key(|node| {
            let gateway = devices
                .get(node)
                .is_some_and(|d| d.role & ROLE_GATEWAY != 0);
            (!gateway, *node)
        });
        due
    }

    /// What a due target needs. `active_first` (pull-behind, §6.3) wins
    /// over staged evidence: the member converges to the host active key
    /// before it stages the new one. Staging never sends Activates —
    /// staged evidence waits for the Activating commit.
    pub fn send_kind(&self, node: u64) -> Option<GkSend> {
        let rotation = self.rotation.as_ref()?;
        let target = self.targets.get(&node)?;
        if target.active_first {
            return Some(GkSend::Update {
                epoch: self.active_epoch,
            });
        }
        match target.row.state {
            TargetState::Pending | TargetState::Unknown => Some(GkSend::Update {
                epoch: rotation.row.to_epoch,
            }),
            TargetState::StagedAcked => match rotation.row.phase {
                RotationPhase::Staging => None,
                RotationPhase::Activating | RotationPhase::CatchingUp => Some(GkSend::Activate {
                    epoch: rotation.row.to_epoch,
                }),
            },
            TargetState::ActiveAcked => None,
        }
    }

    /// Books a command send: 2/4/8 s gaps, then unknown + a 1 min round.
    pub fn note_sent(&mut self, node: u64, activate: bool, mono_ms: u64) {
        let Some(target) = self.targets.get_mut(&node) else {
            return;
        };
        if activate {
            target.activate_sent = true;
        }
        target.attempts += 1;
        if target.attempts >= GK_MAX_ATTEMPTS {
            target.attempts = 0;
            target.next_due_mono = mono_ms.saturating_add(GK_UNKNOWN_RETRY_MS);
            if target.row.state != TargetState::StagedAcked {
                target.row.state = TargetState::Unknown;
            }
            return;
        }
        // attempts is 1..=3 here: the gap after each of the first three sends.
        let delay = GK_RETRY_DELAYS_MS[(target.attempts - 1) as usize];
        target.next_due_mono = mono_ms.saturating_add(delay);
    }

    /// Books a Wake hint: no attempt consumed, just rate-limited.
    pub fn note_wake(&mut self, node: u64, mono_ms: u64) {
        if let Some(target) = self.targets.get_mut(&node) {
            target.next_due_mono = mono_ms.saturating_add(GK_WAKE_RETRY_MS);
        }
    }

    /// Staging finished: full staged evidence (vacuously, zero targets) or
    /// the deadline — never silence alone (§6.2).
    pub fn staging_finished(&self, mono_ms: u64) -> bool {
        let Some(rotation) = self.rotation.as_ref() else {
            return false;
        };
        if rotation.row.phase != RotationPhase::Staging {
            return false;
        }
        mono_ms >= rotation.deadline_mono
            || self.targets.values().all(|t| {
                matches!(
                    t.row.state,
                    TargetState::StagedAcked | TargetState::ActiveAcked
                )
            })
    }

    /// Edge check after recording evidence (ACK) or sending (tick).
    /// Only a staged-but-unsent target holds back catching_up: pending and
    /// unknown targets have no staged evidence an Activate could promote,
    /// so they must not block the phase forever.
    pub fn edge(&self) -> Option<RotationEdge> {
        let rotation = self.rotation.as_ref()?;
        if self
            .targets
            .values()
            .all(|t| t.row.state == TargetState::ActiveAcked)
        {
            return Some(RotationEdge::Converged);
        }
        match rotation.row.phase {
            RotationPhase::Staging => None,
            RotationPhase::Activating
                if !self
                    .targets
                    .values()
                    .any(|t| t.row.state == TargetState::StagedAcked && !t.activate_sent) =>
            {
                Some(RotationEdge::ToCatchingUp)
            }
            RotationPhase::Activating | RotationPhase::CatchingUp => None,
        }
    }

    /// Counts for status and operations: (targets, staged evidence,
    /// active evidence, unknown).
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut staged = 0;
        let mut active = 0;
        let mut unknown = 0;
        for target in self.targets.values() {
            match target.row.state {
                TargetState::StagedAcked => staged += 1,
                TargetState::ActiveAcked => {
                    staged += 1;
                    active += 1;
                }
                TargetState::Pending | TargetState::Unknown => unknown += 1,
            }
        }
        (self.targets.len(), staged, active, unknown)
    }

    // --- RAM publication (called only after the store commit) -----------------

    /// Publishes a staging commit: fresh staged key, live rotation, full
    /// target set. Replaces (and wipes) any superseded staged key.
    pub fn publish_staging(&mut self, plan: StagedPlan) {
        self.staged = Some((plan.to_epoch, GkSecret::new(plan.key)));
        self.staged_created_ms = plan.rotation_row.created_ms;
        // The staged epoch is always exactly high-water + 1 (see
        // `next_epoch`), so publishing it advances the mark.
        self.high_water = plan.to_epoch;
        self.rotation = Some(LiveRotation {
            row: plan.rotation_row,
            deadline_mono: plan.deadline_mono,
        });
        self.targets.clear();
        for target in plan.targets {
            self.targets.insert(target.node, GkTarget::fresh(target));
        }
    }

    /// Publishes the Activating commit: staged becomes active, the old key
    /// is already deleted from the store, the cleanup window starts.
    pub fn publish_activation(&mut self, activated_ms: u64, mono_ms: u64) {
        let Some(rotation) = self.rotation.as_mut() else {
            return;
        };
        if let Some((epoch, key)) = self.staged.take() {
            debug_assert_eq!(epoch, rotation.row.to_epoch);
            self.active_epoch = epoch;
            self.active_key = key;
        }
        rotation.row.phase = RotationPhase::Activating;
        rotation.row.activated_ms = activated_ms;
        self.activated_ms = activated_ms;
        self.cleanup_until_mono = mono_ms.saturating_add(GK_CLEANUP_MS);
        // Every target is due its Activate at once (gateways first).
        for target in self.targets.values_mut() {
            target.attempts = 0;
            target.next_due_mono = 0;
            target.activate_sent = false;
        }
    }

    pub fn publish_catching_up(&mut self) {
        if let Some(rotation) = self.rotation.as_mut() {
            rotation.row.phase = RotationPhase::CatchingUp;
        }
    }

    /// Publishes convergence: the rotation and its targets are gone, the
    /// operation record keeps the terminal state.
    pub fn publish_converged(&mut self, last: LastRotation) {
        self.rotation = None;
        self.targets.clear();
        self.last = Some(last);
    }

    pub fn publish_cleanup(&mut self, mono_ms: u64) {
        self.cleanup_until_mono = mono_ms.saturating_add(GK_CLEANUP_MS);
    }

    pub fn cleanup_until_mono(&self) -> u64 {
        self.cleanup_until_mono
    }

    pub fn add_target(&mut self, row: TargetRow) {
        self.targets.insert(row.node, GkTarget::fresh(row));
    }

    pub fn take_overcap_warned(&mut self) -> bool {
        std::mem::replace(&mut self.overcap_warned, true)
    }

    pub fn clear_overcap_warned(&mut self) {
        self.overcap_warned = false;
    }

    /// `group_keys.status` body (§6.4): phases, causes and counts only —
    /// never secrets, GK-id arrays or DAMS.
    pub fn status_json(&self, time: HostTime) -> String {
        let (targets, staged_ack, active_ack, unknown) = self.counts();
        let (phase, cause, staged) = match &self.rotation {
            Some(rotation) => (
                rotation.row.phase.name(),
                format!("\"{}\"", rotation.row.cause.name()),
                rotation.row.to_epoch.to_string(),
            ),
            None => ("stable", "null".to_string(), "null".to_string()),
        };
        let last = self.last.map_or_else(
            || "null".to_string(),
            |l| {
                format!(
                    "{{\"from\":{},\"to\":{},\"cause\":\"{}\",\"activated_ms\":{}}}",
                    l.from_epoch,
                    l.to_epoch,
                    l.cause.name(),
                    l.activated_ms
                )
            },
        );
        // The next periodic rotation is due 24 h after the activation; a
        // staging/activating rotation owns the slot, so there is no due.
        let next_due = match &self.rotation {
            Some(r)
                if matches!(
                    r.row.phase,
                    RotationPhase::Staging | RotationPhase::Activating
                ) =>
            {
                "null".to_string()
            }
            _ => self
                .activated_ms
                .saturating_add(GK_ROTATION_PERIOD_MS)
                .to_string(),
        };
        format!(
            "{{\"active\":{},\"staged\":{staged},\"phase\":\"{phase}\",\"cause\":{cause},\"targets\":{targets},\"staged_ack\":{staged_ack},\"active_ack\":{active_ack},\"unknown\":{unknown},\"last_rotation\":{last},\"next_due_ms\":{next_due},\"clock\":{{\"unix_ms\":{},\"mono_ms\":{}}}}}",
            self.active_epoch, time.unix_ms, time.mono_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive_log::hex_lower;

    fn plan_9(
        cause: RotationCause,
        phase: RotationPhase,
        deadline: u64,
        targets: Vec<TargetRow>,
    ) -> StagedPlan {
        StagedPlan {
            op_id: 9,
            from_epoch: 1,
            to_epoch: 2,
            key: [2; 32],
            deadline_mono: deadline,
            rotation_row: RotationRow {
                operation_id: 9,
                from_epoch: 1,
                to_epoch: 2,
                cause,
                phase,
                members_revision: 1,
                created_ms: 100,
                activated_ms: 0,
            },
            targets,
            delete_epochs: Vec::new(),
            superseded_op: None,
        }
    }

    #[test]
    fn gk_id_matches_the_independent_hash() {
        // Known answers from `hashlib.sha256` over the §3.1 input (PR1's
        // vector generator pins the same bytes cross-language).
        assert_eq!(
            hex_lower(&gk_id(0x0000_0003_0A1B_2C3D, 2, &[0x5A; 32])),
            "b82774b0190a2d9798f6036116128783f5aecff4ce1d605d92a5729751da4449"
        );
        let mut key = [0_u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            hex_lower(&gk_id(0x0000_0003_0A1B_2C3D, 1, &key)),
            "53b01100f4e7022fbf86f941881e228ffc11709a844dc125852e61c24122b195"
        );
        assert_eq!(
            hex_lower(&gk_id(u64::MAX, u32::MAX, &[0xFF; 32])),
            "2049cb86ce97f9245930c305bf2ad31de76a8ee149802b053834b882b9dcffce"
        );
        // Every input byte matters: network, epoch and key each flip the id.
        let base = gk_id(1, 1, &[7; 32]);
        assert_ne!(gk_id(2, 1, &[7; 32]), base);
        assert_ne!(gk_id(1, 2, &[7; 32]), base);
        assert_ne!(gk_id(1, 1, &[8; 32]), base);
    }

    #[test]
    fn causes_carry_their_wire_values_and_overlaps() {
        assert_eq!(RotationCause::Periodic as u8, 1);
        assert_eq!(RotationCause::Removal as u8, 2);
        assert_eq!(RotationCause::Manual as u8, 3);
        assert_eq!(RotationCause::Periodic.overlap_s(), 60);
        assert_eq!(RotationCause::Manual.overlap_s(), 60);
        assert_eq!(RotationCause::Removal.overlap_s(), 10);
        assert_eq!(RotationCause::parse(0), None);
        assert_eq!(RotationCause::parse(4), None);
        assert_eq!(RotationPhase::parse("bogus"), None);
        assert_eq!(TargetState::parse("bogus"), None);
        for phase in ["staging", "activating", "catching_up"] {
            assert_eq!(RotationPhase::parse(phase).unwrap().name(), phase);
        }
        for state in ["pending", "staged_acked", "active_acked", "unknown"] {
            assert_eq!(TargetState::parse(state).unwrap().name(), state);
        }
    }

    #[test]
    fn the_key_table_validator_refuses_every_corruption() {
        let row = |epoch, state: &str| GroupKeyRow {
            epoch,
            key: [9; 32],
            state: state.into(),
            created_ms: 1,
        };
        // Healthy tables validate.
        let ok = validate_group_keys(&[row(4, "active"), row(5, "staged")], false).unwrap();
        assert_eq!((ok.active_epoch, ok.high_water), (4, 5));
        assert!(validate_group_keys(&[row(4, "active")], false).is_ok());
        // A fresh database reports the sentinel the caller mints epoch 1 on.
        assert!(validate_group_keys(&[], true).is_err());
        // Everything else refuses to start.
        assert!(validate_group_keys(&[], false).is_err());
        assert!(validate_group_keys(&[row(4, "active"), row(6, "active")], false).is_err());
        assert!(validate_group_keys(
            &[row(4, "active"), row(5, "staged"), row(6, "staged")],
            false
        )
        .is_err());
        assert!(validate_group_keys(&[row(5, "staged")], false).is_err());
        assert!(validate_group_keys(&[row(5, "active"), row(4, "staged")], false).is_err());
        assert!(validate_group_keys(&[row(5, "active"), row(5, "staged")], false).is_err());
        assert!(validate_group_keys(&[row(4, "retired")], false).is_err());
        assert!(validate_group_keys(
            &[GroupKeyRow {
                epoch: 4,
                key: [0; 32],
                state: "active".into(),
                created_ms: 1
            }],
            false
        )
        .is_err());
    }

    #[test]
    fn last_rotation_meta_round_trips() {
        for cause in [
            RotationCause::Periodic,
            RotationCause::Removal,
            RotationCause::Manual,
        ] {
            let bytes = encode_last_rotation(7, 8, cause, 123_456);
            assert_eq!(decode_last_rotation(&bytes), Some((7, 8, cause, 123_456)));
        }
        assert_eq!(decode_last_rotation(&[0; 19]), None);
        assert_eq!(decode_last_rotation(&[0; 21]), None);
        let mut bad = encode_last_rotation(7, 8, RotationCause::Manual, 1);
        bad[10] = 1;
        assert_eq!(decode_last_rotation(&bad), None);
    }

    #[test]
    fn the_send_bucket_is_ten_per_second_with_burst_four() {
        let mut gks = GroupRotation::new(1, [1; 32], 1, 100, None);
        for _ in 0..4 {
            assert!(gks.take_token(1_000));
        }
        assert!(!gks.take_token(1_000));
        // 100 ms refills one token; the bucket caps at four.
        assert!(gks.take_token(1_100));
        assert!(!gks.take_token(1_150));
        assert!(gks.take_token(1_250));
        for _ in 0..4 {
            assert!(gks.take_token(10_000));
        }
        assert!(!gks.take_token(10_000));
        // A clock jump backwards grants nothing and panics nothing.
        assert!(!gks.take_token(9_000));
    }

    #[test]
    fn retries_back_off_then_go_unknown_for_a_minute() {
        let mut gks = GroupRotation::new(1, [1; 32], 2, 100, None);
        gks.publish_staging(plan_9(
            RotationCause::Periodic,
            RotationPhase::Staging,
            60_000,
            vec![TargetRow::fresh(9, 0xA1, [3; 32], 1)],
        ));
        assert_eq!(gks.send_kind(0xA1), Some(GkSend::Update { epoch: 2 }));
        gks.note_sent(0xA1, false, 1_000);
        assert_eq!(gks.target(0xA1).unwrap().next_due_mono, 3_000);
        gks.note_sent(0xA1, false, 3_000);
        assert_eq!(gks.target(0xA1).unwrap().next_due_mono, 7_000);
        gks.note_sent(0xA1, false, 7_000);
        assert_eq!(gks.target(0xA1).unwrap().next_due_mono, 15_000);
        gks.note_sent(0xA1, false, 15_000);
        let target = gks.target(0xA1).unwrap();
        assert_eq!(target.row.state, TargetState::Unknown);
        assert_eq!(target.attempts, 0);
        assert_eq!(target.next_due_mono, 75_000);
        // A Wake never consumes an attempt.
        gks.note_wake(0xA1, 75_000);
        let target = gks.target(0xA1).unwrap();
        assert_eq!(target.attempts, 0);
        assert_eq!(target.next_due_mono, 77_000);
    }

    #[test]
    fn due_targets_go_gateways_first() {
        let mut gks = GroupRotation::new(1, [1; 32], 2, 100, None);
        gks.publish_staging(plan_9(
            RotationCause::Removal,
            RotationPhase::Activating,
            0,
            vec![
                TargetRow::fresh(9, 0x30, [3; 32], 1),
                TargetRow::fresh(9, 0x10, [3; 32], 1),
                TargetRow::fresh(9, 0x20, [3; 32], 1),
            ],
        ));
        let mut devices = BTreeMap::new();
        for node in [0x10, 0x20, 0x30] {
            devices.insert(
                node,
                DeviceRow {
                    node,
                    role: if node == 0x20 { ROLE_GATEWAY } else { 1 },
                    ..DeviceRow::default()
                },
            );
        }
        assert_eq!(gks.due_targets(0, &devices), vec![0x20, 0x10, 0x30]);
    }

    #[test]
    fn active_first_wins_over_staged_evidence() {
        let mut gks = GroupRotation::new(1, [1; 32], 2, 100, None);
        gks.publish_staging(plan_9(
            RotationCause::Periodic,
            RotationPhase::Staging,
            60_000,
            vec![TargetRow::fresh(9, 0xA1, [3; 32], 1)],
        ));
        let target = gks.target_mut(0xA1).unwrap();
        target.row.state = TargetState::StagedAcked;
        target.active_first = true;
        assert_eq!(gks.send_kind(0xA1), Some(GkSend::Update { epoch: 1 }));
        // Without the flag, staging sends no Activate for staged evidence:
        // the member waits for the Activating commit.
        gks.target_mut(0xA1).unwrap().active_first = false;
        assert_eq!(gks.send_kind(0xA1), None);
    }

    #[test]
    fn staged_targets_activate_after_the_commit() {
        let mut gks = GroupRotation::new(1, [1; 32], 2, 100, None);
        gks.publish_staging(plan_9(
            RotationCause::Periodic,
            RotationPhase::Staging,
            60_000,
            vec![TargetRow::fresh(9, 0xA1, [3; 32], 1)],
        ));
        gks.target_mut(0xA1).unwrap().row.state = TargetState::StagedAcked;
        gks.publish_activation(200, 1_000);
        assert_eq!(gks.send_kind(0xA1), Some(GkSend::Activate { epoch: 2 }));
    }
}
