//! Authority channel, host side (G-SEC P5 PR1): the bounded RLRES1
//! purpose-4 responder, channel contexts and envelope dispatch behind the
//! Site Authority.
//!
//! The host mirror of the device `AuthorityClient`
//! (`components/routeloom/.../sdkv1_authority.hpp`): it answers R1 with R2,
//! installs on R3, then seals/opens envelopes with real AES-GCM. It owns no
//! member database and no group-key policy — the [`AuthorityDirectory`]
//! answers "which DAMS belongs to this device" (PR3 implements it over the
//! SiteStore), verified business arrives as [`ChannelEvent`]s, and PR3 sends
//! Updates/Activates/Confirms back through this channel. Carriers leave via
//! [`AuthorityTransport`] (PR4 maps them onto USB 0x65 / mesh kind frames).
//!
//! Bounds (P5 §2.2): 4 pending handshakes, 128 channels, 16 R1 nonces, a
//! 10/s burst-4 handshake bucket, 32 outbound carriers and 32 queued
//! events. Re-checks (P5 §4) run the directory at R1 accept, R3 complete,
//! every envelope dispatch and right before every GK send; a removed or
//! reissued member retires its channel instead of using a stale DAMS.

use std::collections::{BTreeMap, VecDeque};

use routeloom_keysched::authority::{
    mac_equal, open_envelope, seal_envelope, BodyHead, GroupKeyAck, GroupKeyActivate, GroupKeyPull,
    GroupKeyUpdate, JoinConfirmDown, JoinConfirmUp, ReplayWindow, BODY_HEAD,
};
use routeloom_keysched::rlres1::{decode_r3, Epochs, R1, R2};
use routeloom_keysched::{
    resume_auth_key, resume_binding_routed, resume_confirm_key, resume_id, resume_mac, resume_prk,
    resume_traffic_key, sha256, Direction, Purpose, ResumeKeyContext, TrafficKey, LABEL_RESUME_R1,
    LABEL_RESUME_R2, LABEL_RESUME_R3,
};
use routeloom_protocol::authority::CarrierKind;
use zeroize::{Zeroize, Zeroizing};

pub use routeloom_keysched::authority::{PullReason, StoredState, UpdateCause, UpdateResult};

pub const MAX_PENDING: usize = 4;
pub const MAX_CHANNELS: usize = 128;
pub const MAX_NONCES: usize = 16;
pub const MAX_OUTBOUND: usize = 32;
pub const MAX_EVENTS: usize = 32;
pub const HANDSHAKE_RATE_PER_S: u32 = 10;
pub const HANDSHAKE_BURST: u32 = 4;
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
pub const IDLE_RETIRE_MS: u64 = 600_000;
pub const PROACTIVE_REKEY_COUNTER: u64 = 1 << 32;

/// Current membership binding, supplied by the owner from its durable row.
/// Every channel operation is fenced by this entire binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ChannelMember {
    pub member: bool,
    pub kid: [u8; 32],
    pub generation: u32,
    pub dams: [u8; 32],
    pub network: u64,
}

impl Drop for ChannelMember {
    fn drop(&mut self) {
        self.dams.zeroize();
    }
}

pub trait AuthorityDirectory {
    /// Current record for `device`, or `None` when removed/unknown. The
    /// The channel compares membership, kid, generation, network and DAMS
    /// across the handshake and every dispatch.
    fn lookup(&self, device: u64) -> Option<ChannelMember>;
}

/// One carrier addressed to a device. PR4 fragments `bytes` onto USB 0x65
/// (or the mesh carrier) under a fresh transfer id.
#[derive(Clone, Debug)]
pub struct AuthorityOutbound {
    pub device: u64,
    pub kind: CarrierKind,
    pub bytes: Vec<u8>,
}

/// Outbound sink. The channel calls it with the lock released (mirroring
/// the JoinTransport discipline), so implementations must be re-entrant
/// safe; `deliver` itself never calls back into the channel. Send + Sync:
/// the service holds it across the lane threads.
pub trait AuthorityTransport: Send + Sync {
    fn deliver(&self, outbound: AuthorityOutbound);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinConfirmFields {
    pub generation: u32,
    pub request_id: u64,
    pub cert_hash: [u8; 32],
    pub boot: u32,
    pub current: u32,
    pub next: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PullFields {
    pub generation: u32,
    pub request_id: u64,
    pub current: u32,
    pub next: u32,
    pub reason: PullReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckFields {
    pub generation: u32,
    pub request_id: u64,
    pub g: u32,
    pub gk_id: [u8; 32],
    pub result: UpdateResult,
    pub stored_state: StoredState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelLostReason {
    Idle,
    StaleMember,
    CounterExhausted,
}

/// Verified business for the owner (PR3). Secret-free: group keys never
/// appear here (they travel host->device only, through the send methods).
#[derive(Clone, Debug)]
pub enum ChannelEvent {
    ChannelReady {
        device: u64,
    },
    ChannelLost {
        device: u64,
        reason: ChannelLostReason,
    },
    JoinConfirm {
        device: u64,
        confirm: JoinConfirmFields,
    },
    Pull {
        device: u64,
        pull: PullFields,
    },
    UpdateAck {
        device: u64,
        ack: AckFields,
    },
    ActivateAck {
        device: u64,
        ack: AckFields,
    },
    Passthrough {
        device: u64,
        env_type: u8,
        body: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelSendError {
    NoChannel,
    StaleMember,
    CounterExhausted,
    OutboundFull,
    InvalidParams,
}

impl std::fmt::Display for ChannelSendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NoChannel => "no channel",
            Self::StaleMember => "stale member",
            Self::CounterExhausted => "counter exhausted",
            Self::OutboundFull => "outbound full",
            Self::InvalidParams => "invalid params",
        };
        formatter.write_str(name)
    }
}

impl std::error::Error for ChannelSendError {}

#[derive(Clone, Copy, Debug)]
pub struct UpdateParams<'a> {
    pub generation: u32,
    pub g: u32,
    pub cause: UpdateCause,
    pub overlap_s: u16,
    pub gk: &'a [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct ActivateParams {
    pub generation: u32,
    pub g: u32,
    pub gk_id: [u8; 32],
    pub cause: UpdateCause,
    pub overlap_s: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct ConfirmParams {
    pub generation: u32,
    pub confirmed_generation: u32,
    pub authority_active: u32,
}

#[derive(Clone, Debug)]
pub struct ChannelConfig {
    pub network: u64,
    pub site_id: u64,
    pub site_epoch: u32,
    pub rs_epoch: u32,
    pub gk_epoch: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ChannelStats {
    pub channels: usize,
    pub pending: usize,
    pub handshakes_completed: u64,
    pub r1_rejected: u64,
    pub envelopes_opened: u64,
    pub envelopes_rejected: u64,
    pub sends: u64,
    pub send_errors: u64,
    pub outbound_dropped: u64,
}

struct PendingHandshake {
    device: u64,
    cid_i: u32,
    cid_r: u32,
    rx_key: TrafficKey,
    tx_key: TrafficKey,
    expected_r3: [u8; 16],
    member: ChannelMember,
    deadline_ms: u64,
}

impl Drop for PendingHandshake {
    fn drop(&mut self) {
        self.rx_key.key.zeroize();
        self.rx_key.iv.zeroize();
        self.tx_key.key.zeroize();
        self.tx_key.iv.zeroize();
        self.expected_r3.zeroize();
    }
}

struct Channel {
    device: u64,
    rx_ctx: u32,
    tx_ctx: u32,
    rx_key: TrafficKey,
    tx_key: TrafficKey,
    rx_window: ReplayWindow,
    tx_counter: u64,
    request_id: u64,
    last_activity_ms: u64,
    member: ChannelMember,
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.rx_key.key.zeroize();
        self.rx_key.iv.zeroize();
        self.tx_key.key.zeroize();
        self.tx_key.iv.zeroize();
    }
}

pub struct AuthorityChannels {
    config: ChannelConfig,
    channels: BTreeMap<u64, Channel>,
    ctx_to_device: BTreeMap<u32, u64>,
    pending: Vec<PendingHandshake>,
    nonces: VecDeque<[u8; 16]>,
    tokens_milli: u32,
    tokens_at_ms: u64,
    tokens_primed: bool,
    next_cid: u32,
    outbound: Vec<AuthorityOutbound>,
    events: VecDeque<ChannelEvent>,
    stats: ChannelStats,
}

impl AuthorityChannels {
    pub fn new(config: ChannelConfig) -> Self {
        Self {
            config,
            channels: BTreeMap::new(),
            ctx_to_device: BTreeMap::new(),
            pending: Vec::new(),
            nonces: VecDeque::new(),
            tokens_milli: 0,
            tokens_at_ms: 0,
            tokens_primed: false,
            next_cid: 1,
            outbound: Vec::new(),
            events: VecDeque::new(),
            stats: ChannelStats::default(),
        }
    }

    pub fn stats(&self) -> ChannelStats {
        let mut stats = self.stats.clone();
        stats.channels = self.channels.len();
        stats.pending = self.pending.len();
        stats
    }

    /// Refreshes the epochs echoed in R2 (the owner calls this after a
    /// revocation or activation commits). Stale R2 epochs would mislead a
    /// joining device about the live revocation/group state; the fence
    /// itself never trusts them, but honesty costs one call.
    pub fn set_epochs(&mut self, rs_epoch: u32, gk_epoch: u32) {
        self.config.rs_epoch = rs_epoch;
        self.config.gk_epoch = gk_epoch;
    }

    pub fn poll_event(&mut self) -> Option<ChannelEvent> {
        self.events.pop_front()
    }

    pub fn take_outbound(&mut self) -> Vec<AuthorityOutbound> {
        std::mem::take(&mut self.outbound)
    }

    /// Delivers every queued outbound carrier through `transport`. The
    /// service loop calls this after each input batch (with its own lock
    /// released); PR4's transport fragments onto USB 0x65 / mesh carriers.
    pub fn drain_to(&mut self, transport: &dyn AuthorityTransport) {
        for outbound in self.take_outbound() {
            transport.deliver(outbound);
        }
    }

    /// Forgets every channel and handshake state for `device` (revocation
    /// fence). Owner-initiated, so no event: the owner already knows.
    pub fn retire_device(&mut self, device: u64) {
        self.pending.retain(|p| p.device != device);
        if let Some(channel) = self.channels.remove(&device) {
            self.ctx_to_device.remove(&channel.rx_ctx);
        }
        self.outbound.retain(|carrier| carrier.device != device);
        self.events.retain(|event| match event {
            ChannelEvent::ChannelReady { device: bound }
            | ChannelEvent::ChannelLost { device: bound, .. }
            | ChannelEvent::JoinConfirm { device: bound, .. }
            | ChannelEvent::Pull { device: bound, .. }
            | ChannelEvent::UpdateAck { device: bound, .. }
            | ChannelEvent::ActivateAck { device: bound, .. }
            | ChannelEvent::Passthrough { device: bound, .. } => *bound != device,
        });
    }

    /// Advances timers: handshake expiry and the 10-minute idle retire.
    pub fn tick(&mut self, now_ms: u64) {
        self.pending.retain(|p| now_ms < p.deadline_ms);
        let idle: Vec<u64> = self
            .channels
            .iter()
            .filter(|(_, c)| now_ms.saturating_sub(c.last_activity_ms) >= IDLE_RETIRE_MS)
            .map(|(device, _)| *device)
            .collect();
        for device in idle {
            self.retire_device(device);
            self.push_event(ChannelEvent::ChannelLost {
                device,
                reason: ChannelLostReason::Idle,
            });
        }
    }

    /// Handles one carrier from `device` (the transport-verified origin).
    /// `rng` fills the responder nonce; a false return drops the R1.
    pub fn on_carrier(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        kind: CarrierKind,
        bytes: &[u8],
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]) -> bool,
    ) {
        match kind {
            CarrierKind::R1 => self.on_r1(directory, device, bytes, now_ms, rng),
            CarrierKind::R3 => self.on_r3(directory, device, bytes, now_ms),
            CarrierKind::Envelope => self.on_envelope(directory, device, bytes, now_ms),
            CarrierKind::R2 | CarrierKind::Wake => {
                // The host never receives R2 (it sends them) and Wake is a
                // host->device hint; either direction here is stray noise.
                self.stats.r1_rejected += 1;
            }
        }
    }

    fn push_event(&mut self, event: ChannelEvent) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        self.events.push_back(event);
    }

    fn binding_current(
        &self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        bound: &ChannelMember,
    ) -> bool {
        directory.lookup(device).is_some_and(|current| {
            current.member && current.network == self.config.network && current == *bound
        })
    }

    fn push_outbound(&mut self, outbound: AuthorityOutbound) -> bool {
        if self.outbound.len() >= MAX_OUTBOUND {
            self.stats.outbound_dropped += 1;
            return false;
        }
        self.outbound.push(outbound);
        true
    }

    fn alloc_cid(&mut self) -> u32 {
        // At most MAX_CHANNELS + MAX_PENDING ids are live, so a short linear
        // probe always finds a free one; 0 means "truly full" (unreachable).
        for _ in 0..MAX_CHANNELS + MAX_PENDING + 2 {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1).max(1);
            if cid != 0
                && !self.ctx_to_device.contains_key(&cid)
                && !self.pending.iter().any(|p| p.cid_r == cid)
            {
                return cid;
            }
        }
        0
    }

    fn take_token(&mut self, now_ms: u64) -> bool {
        let cap = HANDSHAKE_BURST * 1000;
        if !self.tokens_primed {
            self.tokens_primed = true;
            self.tokens_milli = cap;
            self.tokens_at_ms = now_ms;
        } else if now_ms > self.tokens_at_ms {
            // Clamp before scaling: past the clock ceiling the raw product
            // would wrap and starve the bucket instead of refilling it.
            let elapsed = now_ms - self.tokens_at_ms;
            let gained = if elapsed > u64::from(cap) {
                cap
            } else {
                (elapsed as u32)
                    .saturating_mul(HANDSHAKE_RATE_PER_S)
                    .min(cap)
            };
            self.tokens_milli = self.tokens_milli.saturating_add(gained).min(cap);
            self.tokens_at_ms = now_ms;
        }
        if self.tokens_milli < 1000 {
            return false;
        }
        self.tokens_milli -= 1000;
        true
    }

    fn on_r1(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        bytes: &[u8],
        now_ms: u64,
        rng: &mut dyn FnMut(&mut [u8]) -> bool,
    ) {
        let r1 = match R1::decode(bytes) {
            Ok(r1) => r1,
            Err(_) => {
                self.stats.r1_rejected += 1;
                return;
            }
        };
        if r1.purpose != Purpose::Authority
            || !r1.ticket.is_empty()
            || r1.cid_i == 0
            || device == 0
            || device == u64::MAX
            || self.config.network == 0
            || self.config.site_id == 0
            || self.config.site_epoch != (self.config.network >> 32) as u32
        {
            self.stats.r1_rejected += 1;
            return;
        }
        if self
            .channels
            .get(&device)
            .is_some_and(|channel| !self.binding_current(directory, device, &channel.member))
        {
            self.retire_device(device);
            self.push_event(ChannelEvent::ChannelLost {
                device,
                reason: ChannelLostReason::StaleMember,
            });
        }
        let member = match directory.lookup(device) {
            Some(member)
                if member.member
                    && member.generation != 0
                    && member.kid.iter().any(|byte| *byte != 0)
                    && member.dams.iter().any(|byte| *byte != 0)
                    && member.network == self.config.network =>
            {
                member
            }
            _ => {
                self.send_hint(device, &r1.rid);
                self.stats.r1_rejected += 1;
                return;
            }
        };
        if resume_id(&member.dams, Purpose::Authority) != r1.rid {
            self.send_hint(device, &r1.rid);
            self.stats.r1_rejected += 1;
            return;
        }
        let k_auth = Zeroizing::new(resume_auth_key(
            &member.dams,
            Purpose::Authority,
            self.config.network,
            device,
            self.config.site_id,
        ));
        let binding = resume_binding_routed(Purpose::Authority, device, self.config.site_id);
        // The R1 MAC covers the body (everything but the tag); the full
        // bytes — `bytes` itself, which just decoded — feed R2 and the
        // transcript.
        let r1_body = r1.body();
        let mac = resume_mac(&k_auth[..], LABEL_RESUME_R1, &[&binding, &r1_body]);
        if !mac_equal(&mac, &r1.mac) {
            // Wrong key guess: silent, like the engine's BadMac (no hint).
            self.stats.r1_rejected += 1;
            return;
        }
        if self.nonces.contains(&r1.nonce_i) {
            self.stats.r1_rejected += 1;
            return;
        }
        if r1.epochs.site_epoch != self.config.site_epoch {
            self.stats.r1_rejected += 1;
            return;
        }
        if self.pending.iter().any(|p| p.device == device) {
            self.stats.r1_rejected += 1;
            return;
        }
        if self.pending.len() >= MAX_PENDING {
            self.stats.r1_rejected += 1;
            return;
        }
        if self.channels.len() >= MAX_CHANNELS && !self.channels.contains_key(&device) {
            self.stats.r1_rejected += 1;
            return;
        }
        if !self.take_token(now_ms) {
            self.stats.r1_rejected += 1;
            return;
        }
        // The R1 is committed now: burn its nonce (a retry uses a fresh one).
        if self.nonces.len() >= MAX_NONCES {
            self.nonces.pop_front();
        }
        self.nonces.push_back(r1.nonce_i);
        let mut nonce_r = [0_u8; 16];
        if !rng(&mut nonce_r) {
            self.stats.r1_rejected += 1;
            return;
        }
        let cid_r = self.alloc_cid();
        if cid_r == 0 {
            self.stats.r1_rejected += 1;
            return;
        }
        let epochs_r = Epochs {
            site_epoch: self.config.site_epoch,
            rs_epoch: self.config.rs_epoch,
            gk_epoch: self.config.gk_epoch,
        };
        let r2_body = R2::ok_body(&nonce_r, cid_r, &epochs_r);
        let mac_r = resume_mac(&k_auth[..], LABEL_RESUME_R2, &[&binding, bytes, &r2_body]);
        let mut r2_bytes = r2_body;
        r2_bytes.extend_from_slice(&mac_r);
        let context = ResumeKeyContext {
            purpose: Purpose::Authority,
            network: self.config.network,
            node_i: device,
            node_r: self.config.site_id,
            cid_i: r1.cid_i,
            cid_r,
        };
        let th = sha256(&[bytes, &r2_bytes]);
        let prk = Zeroizing::new(resume_prk(&r1.nonce_i, &nonce_r, &member.dams));
        let k_conf = Zeroizing::new(resume_confirm_key(&prk, &th));
        let expected_r3 = resume_mac(&k_conf[..], LABEL_RESUME_R3, &[&th]);
        let pending = PendingHandshake {
            device,
            cid_i: r1.cid_i,
            cid_r,
            rx_key: resume_traffic_key(&prk, &context, Direction::InitiatorToResponder, &th),
            tx_key: resume_traffic_key(&prk, &context, Direction::ResponderToInitiator, &th),
            expected_r3,
            member,
            deadline_ms: now_ms.saturating_add(HANDSHAKE_TIMEOUT_MS),
        };
        // The outbound must have room before the pending slot is spent: a
        // stored handshake whose R2 never leaves would only burn the retry.
        if self.outbound.len() >= MAX_OUTBOUND {
            self.stats.outbound_dropped += 1;
            self.stats.r1_rejected += 1;
            return;
        }
        self.pending.push(pending);
        self.push_outbound(AuthorityOutbound {
            device,
            kind: CarrierKind::R2,
            bytes: r2_bytes,
        });
    }

    fn send_hint(&mut self, device: u64, rid: &[u8; 8]) {
        let hint = R2::Hint {
            status: 1,
            rid: *rid,
        }
        .encode();
        self.push_outbound(AuthorityOutbound {
            device,
            kind: CarrierKind::R2,
            bytes: hint,
        });
    }

    fn on_r3(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        bytes: &[u8],
        now_ms: u64,
    ) {
        let r3 = match decode_r3(bytes) {
            Ok(r3) => r3,
            Err(_) => {
                self.stats.r1_rejected += 1;
                return;
            }
        };
        let slot = match self.pending.iter().position(|p| p.device == device) {
            Some(slot) => slot,
            None => {
                self.stats.r1_rejected += 1;
                return;
            }
        };
        let pending = &self.pending[slot];
        if now_ms >= pending.deadline_ms {
            self.pending.remove(slot);
            self.stats.r1_rejected += 1;
            return;
        }
        if !mac_equal(&r3, &pending.expected_r3) {
            self.stats.r1_rejected += 1;
            return;
        }
        // R3-complete re-check: the member may have been removed or reissued
        // between R1 and R3.
        if !self.binding_current(directory, device, &pending.member) {
            self.pending.remove(slot);
            self.stats.r1_rejected += 1;
            return;
        }
        if self.channels.len() >= MAX_CHANNELS && !self.channels.contains_key(&device) {
            self.stats.r1_rejected += 1;
            return;
        }
        if self.events.len() >= MAX_EVENTS {
            self.stats.r1_rejected += 1;
            return;
        }
        let pending = self.pending.remove(slot);
        if self.channels.contains_key(&device) {
            self.retire_device(device);
        }
        self.ctx_to_device.insert(pending.cid_r, device);
        self.channels.insert(
            device,
            Channel {
                device,
                rx_ctx: pending.cid_r,
                tx_ctx: pending.cid_i,
                rx_key: pending.rx_key,
                tx_key: pending.tx_key,
                rx_window: ReplayWindow::new(),
                tx_counter: 0,
                request_id: 1,
                last_activity_ms: now_ms,
                member: pending.member.clone(),
            },
        );
        self.stats.handshakes_completed += 1;
        self.push_event(ChannelEvent::ChannelReady { device });
    }

    fn on_envelope(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        bytes: &[u8],
        now_ms: u64,
    ) {
        if device == 0 || device == u64::MAX {
            self.stats.envelopes_rejected += 1;
            return;
        }
        let header = match routeloom_keysched::AuthorityEnvelopeHeader::decode(bytes) {
            Ok(header) => header,
            Err(_) => {
                self.stats.envelopes_rejected += 1;
                return;
            }
        };
        // The envelope ctx selects the channel — never the claimed device.
        // The channel's bound device must then equal the claim, or a
        // mislabelled carrier could cross into another member's channel.
        let bound = match self.ctx_to_device.get(&header.ctx_id) {
            Some(bound) => *bound,
            None => {
                self.stats.envelopes_rejected += 1;
                return;
            }
        };
        if bound != device {
            self.stats.envelopes_rejected += 1;
            return;
        }
        // Dispatch-time re-check: a removed or reissued member retires its
        // channel instead of answering under a stale DAMS.
        let stale = !self
            .channels
            .get(&device)
            .is_some_and(|c| self.binding_current(directory, device, &c.member));
        if stale {
            self.retire_device(device);
            self.stats.envelopes_rejected += 1;
            self.push_event(ChannelEvent::ChannelLost {
                device,
                reason: ChannelLostReason::StaleMember,
            });
            return;
        }
        // The caller may retry the same ciphertext after draining events.
        // Preserve its replay slot until the verified business can be queued.
        if self.events.len() >= MAX_EVENTS {
            self.stats.envelopes_rejected += 1;
            return;
        }
        let channel = match self.channels.get_mut(&device) {
            Some(channel) => channel,
            None => {
                self.stats.envelopes_rejected += 1;
                return;
            }
        };
        let (header, plaintext) = match open_envelope(&channel.rx_key, bytes, channel.rx_ctx) {
            Ok(opened) => opened,
            Err(_) => {
                self.stats.envelopes_rejected += 1;
                return;
            }
        };
        if !channel.rx_window.accept(header.counter) {
            self.stats.envelopes_rejected += 1;
            return;
        }
        channel.last_activity_ms = now_ms;
        self.stats.envelopes_opened += 1;
        let generation = channel.member.generation;
        match header.env_type {
            1 => match JoinConfirmUp::decode(&plaintext) {
                Ok(up) if up.head.generation == generation => {
                    self.push_event(ChannelEvent::JoinConfirm {
                        device,
                        confirm: JoinConfirmFields {
                            generation: up.head.generation,
                            request_id: up.head.request_id,
                            cert_hash: up.cert_hash,
                            boot: up.boot,
                            current: up.current,
                            next: up.next,
                        },
                    })
                }
                _ => self.stats.envelopes_rejected += 1,
            },
            4 => match GroupKeyPull::decode(&plaintext) {
                Ok(pull) if pull.head.generation == generation => {
                    self.push_event(ChannelEvent::Pull {
                        device,
                        pull: PullFields {
                            generation: pull.head.generation,
                            request_id: pull.head.request_id,
                            current: pull.current,
                            next: pull.next,
                            reason: pull.reason,
                        },
                    })
                }
                _ => self.stats.envelopes_rejected += 1,
            },
            2 => match GroupKeyAck::decode(&plaintext) {
                Ok(ack) if ack.head.generation == generation => {
                    self.push_event(ChannelEvent::UpdateAck {
                        device,
                        ack: AckFields {
                            generation: ack.head.generation,
                            request_id: ack.head.request_id,
                            g: ack.g,
                            gk_id: ack.gk_id,
                            result: ack.result,
                            stored_state: ack.stored_state,
                        },
                    })
                }
                _ => self.stats.envelopes_rejected += 1,
            },
            3 => match GroupKeyAck::decode(&plaintext) {
                Ok(ack) if ack.head.generation == generation => {
                    self.push_event(ChannelEvent::ActivateAck {
                        device,
                        ack: AckFields {
                            generation: ack.head.generation,
                            request_id: ack.head.request_id,
                            g: ack.g,
                            gk_id: ack.gk_id,
                            result: ack.result,
                            stored_state: ack.stored_state,
                        },
                    })
                }
                _ => self.stats.envelopes_rejected += 1,
            },
            env_type => {
                // Types 5..8: AEAD-verified plaintext for the P6 sink. The
                // head must still be well-formed; the tail stays opaque.
                let head_ok = plaintext.len() >= BODY_HEAD
                    && BodyHead::decode(&plaintext[..BODY_HEAD], plaintext[1])
                        .is_ok_and(|head| head.generation == generation);
                if head_ok {
                    self.push_event(ChannelEvent::Passthrough {
                        device,
                        env_type,
                        body: plaintext,
                    });
                } else {
                    self.stats.envelopes_rejected += 1;
                }
            }
        }
    }

    fn seal_for(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        env_type: u8,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<(), ChannelSendError> {
        // Pre-send re-check: never seal under a stale DAMS.
        let stale = !self
            .channels
            .get(&device)
            .is_some_and(|c| self.binding_current(directory, device, &c.member));
        if stale {
            self.retire_device(device);
            self.stats.send_errors += 1;
            self.push_event(ChannelEvent::ChannelLost {
                device,
                reason: ChannelLostReason::StaleMember,
            });
            return Err(ChannelSendError::StaleMember);
        }
        if self.outbound.len() >= MAX_OUTBOUND {
            self.stats.send_errors += 1;
            return Err(ChannelSendError::OutboundFull);
        }
        let channel = match self.channels.get_mut(&device) {
            Some(channel) => channel,
            None => {
                self.stats.send_errors += 1;
                return Err(ChannelSendError::NoChannel);
            }
        };
        if channel.tx_counter >= PROACTIVE_REKEY_COUNTER {
            // 2^32 envelopes on one context: retire before the 2^48 hard
            // stop. The owner re-establishes (WakeLocal) on demand.
            let device = channel.device;
            self.retire_device(device);
            self.stats.send_errors += 1;
            self.push_event(ChannelEvent::ChannelLost {
                device,
                reason: ChannelLostReason::CounterExhausted,
            });
            return Err(ChannelSendError::CounterExhausted);
        }
        if channel.request_id == u64::MAX {
            let device = channel.device;
            self.retire_device(device);
            self.stats.send_errors += 1;
            self.push_event(ChannelEvent::ChannelLost {
                device,
                reason: ChannelLostReason::CounterExhausted,
            });
            return Err(ChannelSendError::CounterExhausted);
        }
        let op = if env_type == 1 { 2 } else { 1 };
        if !BodyHead::decode(plaintext, op)
            .is_ok_and(|head| head.generation == channel.member.generation)
        {
            self.stats.send_errors += 1;
            return Err(ChannelSendError::InvalidParams);
        }
        let counter = channel.tx_counter;
        channel.tx_counter += 1;
        let envelope = match seal_envelope(
            &channel.tx_key,
            env_type,
            channel.tx_ctx,
            counter,
            plaintext,
        ) {
            Ok(envelope) => envelope,
            Err(_) => {
                self.stats.send_errors += 1;
                return Err(ChannelSendError::CounterExhausted);
            }
        };
        channel.request_id += 1;
        channel.last_activity_ms = now_ms;
        self.stats.sends += 1;
        self.push_outbound(AuthorityOutbound {
            device,
            kind: CarrierKind::Envelope,
            bytes: envelope,
        });
        Ok(())
    }

    fn alloc_request_id(&mut self, device: u64) -> Result<u64, ChannelSendError> {
        let id = match self.channels.get(&device) {
            None => return Err(ChannelSendError::NoChannel),
            Some(channel) => channel.request_id,
        };
        if id == u64::MAX {
            // The id space wrapped: end the channel before any id is reused.
            self.retire_device(device);
            self.stats.send_errors += 1;
            self.push_event(ChannelEvent::ChannelLost {
                device,
                reason: ChannelLostReason::CounterExhausted,
            });
            return Err(ChannelSendError::CounterExhausted);
        }
        Ok(id)
    }

    /// Seals a GroupKeyUpdate for `device` (PR3: GK distribution).
    pub fn send_update(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        params: UpdateParams<'_>,
        now_ms: u64,
    ) -> Result<(), ChannelSendError> {
        if params.gk.iter().all(|b| *b == 0) {
            return Err(ChannelSendError::InvalidParams);
        }
        let request_id = self.alloc_request_id(device)?;
        let update = GroupKeyUpdate {
            head: BodyHead {
                op: 1,
                generation: params.generation,
                request_id,
            },
            g: params.g,
            cause: params.cause,
            overlap_s: params.overlap_s,
            gk: *params.gk,
        };
        let mut plaintext = update
            .encode()
            .map_err(|_| ChannelSendError::InvalidParams)?;
        let sent = self.seal_for(directory, device, 2, &plaintext, now_ms);
        plaintext.zeroize();
        sent
    }

    /// Seals a GroupKeyActivate for `device` (PR3: GK activation).
    pub fn send_activate(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        params: ActivateParams,
        now_ms: u64,
    ) -> Result<(), ChannelSendError> {
        let request_id = self.alloc_request_id(device)?;
        let activate = GroupKeyActivate {
            head: BodyHead {
                op: 1,
                generation: params.generation,
                request_id,
            },
            g: params.g,
            gk_id: params.gk_id,
            cause: params.cause,
            overlap_s: params.overlap_s,
        };
        let plaintext = activate
            .encode()
            .map_err(|_| ChannelSendError::InvalidParams)?;
        self.seal_for(directory, device, 3, &plaintext, now_ms)
    }

    /// Answers a JoinConfirm for `device` (PR3: after persisting it).
    pub fn answer_join_confirm(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        params: ConfirmParams,
        now_ms: u64,
    ) -> Result<(), ChannelSendError> {
        let request_id = self.alloc_request_id(device)?;
        let confirm = JoinConfirmDown {
            head: BodyHead {
                op: 2,
                generation: params.generation,
                request_id,
            },
            confirmed_generation: params.confirmed_generation,
            authority_active: params.authority_active,
        };
        let plaintext = confirm
            .encode()
            .map_err(|_| ChannelSendError::InvalidParams)?;
        self.seal_for(directory, device, 1, &plaintext, now_ms)
    }

    /// Queues an unsealed kind-5 Wake hint for `device` (P5 §3.2: the
    /// only carrier that needs no channel). The 8 B body carries the
    /// owner's site/gk epochs so the device can tell a stale hint from a
    /// live one; it changes no key, generation, floor or membership, and
    /// the device answers by opening R1 as initiator. Still fenced on the
    /// live row: a removed or unknown device is `StaleMember`, never a
    /// hint to a stranger.
    pub fn queue_wake(
        &mut self,
        directory: &dyn AuthorityDirectory,
        device: u64,
        site_epoch: u32,
        gk_epoch: u32,
    ) -> Result<(), ChannelSendError> {
        let member = directory.lookup(device).filter(|row| row.member);
        if member.is_none() {
            self.stats.send_errors += 1;
            return Err(ChannelSendError::StaleMember);
        }
        if self.outbound.len() >= MAX_OUTBOUND {
            self.stats.send_errors += 1;
            return Err(ChannelSendError::OutboundFull);
        }
        let mut body = [0_u8; 8];
        body[..4].copy_from_slice(&site_epoch.to_be_bytes());
        body[4..].copy_from_slice(&gk_epoch.to_be_bytes());
        self.stats.sends += 1;
        self.push_outbound(AuthorityOutbound {
            device,
            kind: CarrierKind::Wake,
            bytes: body.to_vec(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::testkit::{AuthorityNet, FakeDevice};
    use routeloom_keysched::authority::gk_id;
    use routeloom_keysched::rlres1::{Epochs, R3_SIZE};

    const NETWORK: u64 = (7 << 32) | 0x0A0B0C0D;
    const SITE: u64 = 0x5100000000000042;
    const DEVICE: u64 = 0x101;

    fn net() -> AuthorityNet {
        AuthorityNet {
            network: NETWORK,
            site: SITE,
            epochs_i: Epochs {
                site_epoch: 7,
                rs_epoch: 2,
                gk_epoch: 10,
            },
            epochs_r: Epochs {
                site_epoch: 7,
                rs_epoch: 4,
                gk_epoch: 12,
            },
        }
    }

    fn dams() -> [u8; 32] {
        let mut dams = [0_u8; 32];
        for (i, b) in dams.iter_mut().enumerate() {
            *b = 0xD0_u8.wrapping_add(i as u8);
        }
        dams
    }

    #[derive(Default)]
    struct FakeDirectory {
        devices: BTreeMap<u64, ChannelMember>,
    }

    impl FakeDirectory {
        fn with(device: u64, dams: [u8; 32]) -> Self {
            let mut directory = Self::default();
            directory.devices.insert(
                device,
                ChannelMember {
                    member: true,
                    kid: [0xC1; 32],
                    generation: 9,
                    dams,
                    network: NETWORK,
                },
            );
            directory
        }
    }

    impl AuthorityDirectory for FakeDirectory {
        fn lookup(&self, device: u64) -> Option<ChannelMember> {
            self.devices.get(&device).cloned()
        }
    }

    fn config() -> ChannelConfig {
        ChannelConfig {
            network: NETWORK,
            site_id: SITE,
            site_epoch: 7,
            rs_epoch: 4,
            gk_epoch: 12,
        }
    }

    fn rng(state: &mut u64) -> impl FnMut(&mut [u8]) -> bool + '_ {
        |out: &mut [u8]| {
            for b in out.iter_mut() {
                *state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (*state >> 33) as u8;
            }
            true
        }
    }

    fn drain_r2(channels: &mut AuthorityChannels) -> Vec<u8> {
        let outbound = channels.take_outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, CarrierKind::R2);
        assert_eq!(outbound[0].bytes.len(), routeloom_keysched::rlres1::R2_OK);
        outbound.into_iter().next().expect("R2").bytes
    }

    fn handshake_at(
        channels: &mut AuthorityChannels,
        directory: &FakeDirectory,
        cid_i: u32,
        nonce_i: [u8; 16],
        now_ms: u64,
    ) -> FakeDevice {
        let mut state = 0x1234_5678_9ABC_DEF0;
        let (r1, mut device) = FakeDevice::begin(DEVICE, dams(), cid_i, nonce_i, net());
        channels.on_carrier(
            directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            now_ms,
            &mut rng(&mut state),
        );
        let r2 = drain_r2(channels);
        let r3 = device.on_r2(&r2);
        assert_eq!(r3.len(), R3_SIZE);
        channels.on_carrier(
            directory,
            DEVICE,
            CarrierKind::R3,
            &r3,
            now_ms,
            &mut rng(&mut state),
        );
        assert!(matches!(
            channels.poll_event(),
            Some(ChannelEvent::ChannelReady { device: DEVICE })
        ));
        device
    }

    fn handshake(channels: &mut AuthorityChannels, directory: &FakeDirectory) -> FakeDevice {
        let device = handshake_at(channels, directory, 0xA001, [0x11; 16], 1000);
        assert_eq!(channels.stats().handshakes_completed, 1);
        device
    }

    #[test]
    fn round_trip_join_confirm_pull_update_activate() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut device = handshake(&mut channels, &directory);

        // JoinConfirm up, answered down.
        let up = JoinConfirmUp {
            head: BodyHead {
                op: 1,
                generation: 9,
                request_id: 1,
            },
            cert_hash: [0xC0; 32],
            boot: 5,
            current: 10,
            next: 0,
        }
        .encode()
        .expect("encode");
        let mut state = 0x99;
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(1, &up),
            1000,
            &mut rng(&mut state),
        );
        let confirm = match channels.poll_event() {
            Some(ChannelEvent::JoinConfirm { device, confirm }) => {
                assert_eq!(device, DEVICE);
                confirm
            }
            other => panic!("expected JoinConfirm, got {other:?}"),
        };
        assert_eq!(confirm.boot, 5);
        channels
            .answer_join_confirm(
                &directory,
                DEVICE,
                ConfirmParams {
                    generation: 9,
                    confirmed_generation: confirm.generation,
                    authority_active: 10,
                },
                1000,
            )
            .expect("answer");
        let reply = channels.take_outbound();
        assert_eq!(reply.len(), 1);
        let (env_type, plaintext) = device.open(&reply[0].bytes);
        assert_eq!(env_type, 1);
        let down = JoinConfirmDown::decode(&plaintext).expect("decode");
        assert_eq!(down.confirmed_generation, 9);

        // Pull up, answered with an Update carrying a real GK.
        let pull = GroupKeyPull {
            head: BodyHead {
                op: 1,
                generation: 9,
                request_id: 2,
            },
            current: 10,
            next: 0,
            reason: PullReason::BootReconnectSync,
        }
        .encode()
        .expect("encode");
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(4, &pull),
            1000,
            &mut rng(&mut state),
        );
        match channels.poll_event() {
            Some(ChannelEvent::Pull { device, pull }) => {
                assert_eq!(device, DEVICE);
                assert_eq!(pull.current, 10);
                assert_eq!(pull.reason, PullReason::BootReconnectSync);
            }
            other => panic!("expected Pull, got {other:?}"),
        }
        let gk = [0xA0; 32];
        channels
            .send_update(
                &directory,
                DEVICE,
                UpdateParams {
                    generation: 9,
                    g: 11,
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                    gk: &gk,
                },
                1000,
            )
            .expect("send update");
        let reply = channels.take_outbound();
        assert_eq!(reply.len(), 1);
        let (env_type, plaintext) = device.open(&reply[0].bytes);
        assert_eq!(env_type, 2);
        let update = GroupKeyUpdate::decode(&plaintext).expect("decode");
        assert_eq!(update.gk, gk);

        // The ACK comes back and the GK-id matches the sent key.
        let ack = GroupKeyAck {
            head: BodyHead {
                op: 2,
                generation: 9,
                request_id: 3,
            },
            g: 11,
            gk_id: gk_id(NETWORK, 11, &gk),
            result: UpdateResult::Durable,
            stored_state: StoredState::Staged,
        }
        .encode()
        .expect("encode");
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(2, &ack),
            1000,
            &mut rng(&mut state),
        );
        match channels.poll_event() {
            Some(ChannelEvent::UpdateAck { device, ack }) => {
                assert_eq!(device, DEVICE);
                assert_eq!(ack.result, UpdateResult::Durable);
                assert_eq!(ack.gk_id, gk_id(NETWORK, 11, &gk));
            }
            other => panic!("expected UpdateAck, got {other:?}"),
        }

        // Activate down, ACK up.
        channels
            .send_activate(
                &directory,
                DEVICE,
                ActivateParams {
                    generation: 9,
                    g: 11,
                    gk_id: gk_id(NETWORK, 11, &gk),
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                },
                1000,
            )
            .expect("send activate");
        let reply = channels.take_outbound();
        assert_eq!(reply.len(), 1);
        let (env_type, _) = device.open(&reply[0].bytes);
        assert_eq!(env_type, 3);
        let ack = GroupKeyAck {
            head: BodyHead {
                op: 2,
                generation: 9,
                request_id: 4,
            },
            g: 11,
            gk_id: gk_id(NETWORK, 11, &gk),
            result: UpdateResult::Durable,
            stored_state: StoredState::Active,
        }
        .encode()
        .expect("encode");
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(3, &ack),
            1000,
            &mut rng(&mut state),
        );
        match channels.poll_event() {
            Some(ChannelEvent::ActivateAck { device, ack }) => {
                assert_eq!(device, DEVICE);
                assert_eq!(ack.g, 11);
                assert_eq!(ack.stored_state, StoredState::Active);
            }
            other => panic!("expected ActivateAck, got {other:?}"),
        }
        assert_eq!(channels.stats().envelopes_opened, 4);
    }

    #[test]
    fn handshake_rejects_and_recovers() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut state = 0x55;

        // Unknown device: R2 hint, no channel.
        let (r1, _) = FakeDevice::begin(DEVICE, dams(), 0xA001, [0x11; 16], net());
        channels.on_carrier(
            &directory,
            0x999,
            CarrierKind::R1,
            &r1,
            1000,
            &mut rng(&mut state),
        );
        let outbound = channels.take_outbound();
        assert_eq!(outbound.len(), 1);
        assert!(matches!(
            R2::decode(&outbound[0].bytes),
            Ok(R2::Hint { status: 1, .. })
        ));
        assert_eq!(channels.stats().r1_rejected, 1);

        // Right device, wrong DAMS guess: silent (no oracle beyond the rid).
        let (r1, _) = FakeDevice::begin(DEVICE, [0xEE; 32], 0xA001, [0x22; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1000,
            &mut rng(&mut state),
        );
        assert!(channels.take_outbound().len() <= 1);
        assert_eq!(channels.stats().r1_rejected, 2);

        // The real device still handshakes afterwards.
        let directory = FakeDirectory::with(DEVICE, dams());
        let _device = handshake(&mut channels, &directory);
        assert_eq!(channels.channels.len(), 1);
    }

    #[test]
    fn envelope_attacks_are_contained() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut device = handshake(&mut channels, &directory);
        let mut state = 0x77;
        let feed = |channels: &mut AuthorityChannels,
                    directory: &FakeDirectory,
                    device: u64,
                    bytes: &[u8],
                    state: &mut u64| {
            channels.on_carrier(
                directory,
                device,
                CarrierKind::Envelope,
                bytes,
                1000,
                &mut rng(state),
            );
        };

        // A flipped bit fails authentication and leaves the replay window
        // unmoved: the intact envelope still opens afterwards.
        let pull = GroupKeyPull {
            head: BodyHead {
                op: 1,
                generation: 9,
                request_id: 7,
            },
            current: 10,
            next: 0,
            reason: PullReason::BootReconnectSync,
        }
        .encode()
        .expect("encode");
        let good = device.seal(4, &pull);
        let mut tampered = good.clone();
        tampered[20] ^= 0x01;
        feed(&mut channels, &directory, DEVICE, &tampered, &mut state);
        assert!(channels.poll_event().is_none());
        feed(&mut channels, &directory, DEVICE, &good, &mut state);
        match channels.poll_event() {
            Some(ChannelEvent::Pull { device, pull }) => {
                assert_eq!(device, DEVICE);
                assert_eq!(pull.request_id, 7);
            }
            other => panic!("expected Pull, got {other:?}"),
        }
        // The same bytes again: a replay, contained.
        feed(&mut channels, &directory, DEVICE, &good, &mut state);
        assert!(channels.poll_event().is_none());

        // Claim the intact envelope for the wrong device: the channel's
        // bound device wins over the transport claim, so nothing dispatches.
        feed(&mut channels, &directory, 0x202, &good, &mut state);
        assert!(channels.poll_event().is_none());

        // A wrong-direction Update (op 1) addressed to the host: refused.
        let gk = [0xA0; 32];
        let update = GroupKeyUpdate {
            head: BodyHead {
                op: 1,
                generation: 9,
                request_id: 8,
            },
            g: 11,
            cause: UpdateCause::Periodic,
            overlap_s: 60,
            gk,
        }
        .encode()
        .expect("encode");
        let wrong_dir = device.seal(2, &update);
        feed(&mut channels, &directory, DEVICE, &wrong_dir, &mut state);
        assert!(channels.poll_event().is_none());
        assert!(channels.stats().envelopes_rejected >= 4);
    }

    #[test]
    fn removal_and_reissue_retire_the_channel() {
        let mut directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut device = handshake(&mut channels, &directory);

        // Removal between messages: the next envelope retires the channel.
        directory.devices.remove(&DEVICE);
        let pull = GroupKeyPull {
            head: BodyHead {
                op: 1,
                generation: 9,
                request_id: 9,
            },
            current: 10,
            next: 0,
            reason: PullReason::BootReconnectSync,
        }
        .encode()
        .expect("encode");
        let mut state = 0x11;
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(4, &pull),
            1000,
            &mut rng(&mut state),
        );
        match channels.poll_event() {
            Some(ChannelEvent::ChannelLost { device, reason }) => {
                assert_eq!(device, DEVICE);
                assert_eq!(reason, ChannelLostReason::StaleMember);
            }
            other => panic!("expected ChannelLost, got {other:?}"),
        }
        assert_eq!(channels.stats().channels, 0);

        // Reissue with a new DAMS: the old handshake's R3 is stale, a fresh
        // handshake works.
        let directory = FakeDirectory::with(DEVICE, [0xE0; 32]);
        let mut channels = AuthorityChannels::new(config());
        let mut state = 0x22;
        let (r1, _) = FakeDevice::begin(DEVICE, dams(), 0xA001, [0x44; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1000,
            &mut rng(&mut state),
        );
        // Old DAMS, new directory: rid mismatch -> hint, no channel.
        let outbound = channels.take_outbound();
        assert_eq!(outbound.len(), 1);
        assert!(matches!(
            R2::decode(&outbound[0].bytes),
            Ok(R2::Hint { .. })
        ));
    }

    #[test]
    fn idle_channels_retire_and_sends_fail_closed() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let _device = handshake(&mut channels, &directory);
        channels.tick(1000 + IDLE_RETIRE_MS);
        match channels.poll_event() {
            Some(ChannelEvent::ChannelLost { device, reason }) => {
                assert_eq!(device, DEVICE);
                assert_eq!(reason, ChannelLostReason::Idle);
            }
            other => panic!("expected ChannelLost, got {other:?}"),
        }
        assert_eq!(
            channels
                .send_update(
                    &directory,
                    DEVICE,
                    UpdateParams {
                        generation: 9,
                        g: 11,
                        cause: UpdateCause::Periodic,
                        overlap_s: 60,
                        gk: &[0xA0; 32],
                    },
                    1000,
                )
                .unwrap_err(),
            ChannelSendError::NoChannel
        );
        // A zero GK is never sealed, even with a live channel.
        let _device = handshake_at(&mut channels, &directory, 0xA002, [0x66; 16], 700_000);
        assert_eq!(
            channels
                .send_update(
                    &directory,
                    DEVICE,
                    UpdateParams {
                        generation: 9,
                        g: 11,
                        cause: UpdateCause::Periodic,
                        overlap_s: 60,
                        gk: &[0; 32],
                    },
                    1000,
                )
                .unwrap_err(),
            ChannelSendError::InvalidParams
        );
        // A removal/60 s mismatch is refused by the shared codec rule.
        assert_eq!(
            channels
                .send_update(
                    &directory,
                    DEVICE,
                    UpdateParams {
                        generation: 9,
                        g: 11,
                        cause: UpdateCause::Removal,
                        overlap_s: 60,
                        gk: &[0xA0; 32],
                    },
                    1000,
                )
                .unwrap_err(),
            ChannelSendError::InvalidParams
        );
    }

    #[test]
    fn responder_is_bounded() {
        let mut channels = AuthorityChannels::new(config());
        let mut state = 0x33;
        // Five distinct devices race one valid R1 each: the first four
        // occupy the pending table, the fifth is dropped.
        let mut directory = FakeDirectory::default();
        for device in 0x300..0x305 {
            directory.devices.insert(
                device,
                ChannelMember {
                    member: true,
                    kid: [0xC1; 32],
                    generation: 9,
                    dams: dams(),
                    network: NETWORK,
                },
            );
        }
        for (i, device) in (0x300..0x305).enumerate() {
            let (r1, _) =
                FakeDevice::begin(device, dams(), 0xA001 + i as u32, [device as u8; 16], net());
            channels.on_carrier(
                &directory,
                device,
                CarrierKind::R1,
                &r1,
                1000,
                &mut rng(&mut state),
            );
        }
        assert_eq!(channels.stats().pending, MAX_PENDING);
        // A second R1 from a pending device is dropped, not queued.
        let (r1dup, _) = FakeDevice::begin(0x300, dams(), 0xB000, [0x52; 16], net());
        channels.on_carrier(
            &directory,
            0x300,
            CarrierKind::R1,
            &r1dup,
            1000,
            &mut rng(&mut state),
        );
        assert_eq!(channels.stats().pending, MAX_PENDING);
        // Expiry reaps the pending slots.
        channels.tick(1000 + HANDSHAKE_TIMEOUT_MS + 1);
        assert_eq!(channels.stats().pending, 0);
    }

    #[test]
    fn future_types_reach_the_passthrough_sink() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut device = handshake(&mut channels, &directory);
        // A type-6 body with a well-formed head passes through verbatim.
        let mut body = BodyHead {
            op: 1,
            generation: 9,
            request_id: 0x55,
        }
        .encode(1)
        .expect("head")
        .to_vec();
        body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut state = 0x44;
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(6, &body),
            1000,
            &mut rng(&mut state),
        );
        match channels.poll_event() {
            Some(ChannelEvent::Passthrough {
                device,
                env_type,
                body: passed,
            }) => {
                assert_eq!(device, DEVICE);
                assert_eq!(env_type, 6);
                assert_eq!(passed, body);
            }
            other => panic!("expected Passthrough, got {other:?}"),
        }
        // A bad head under a valid tag does not.
        body[0] = 2;
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(6, &body),
            1000,
            &mut rng(&mut state),
        );
        assert!(channels.poll_event().is_none());
    }

    #[test]
    fn drain_to_delivers_through_the_transport() {
        use std::sync::Mutex;
        struct Record {
            inner: Mutex<Vec<AuthorityOutbound>>,
        }
        impl AuthorityTransport for Record {
            fn deliver(&self, outbound: AuthorityOutbound) {
                self.inner.lock().expect("lock").push(outbound);
            }
        }
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let transport = Record {
            inner: Mutex::new(Vec::new()),
        };
        let mut state = 0x12;
        let (r1, _) = FakeDevice::begin(DEVICE, dams(), 0xA001, [0x71; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1000,
            &mut rng(&mut state),
        );
        channels.drain_to(&transport);
        let delivered = transport.inner.lock().expect("lock");
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].device, DEVICE);
        assert_eq!(delivered[0].kind, CarrierKind::R2);
        assert!(channels.take_outbound().is_empty());
    }

    #[test]
    fn directory_network_change_retires_before_send() {
        let mut directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let _device = handshake(&mut channels, &directory);
        directory.devices.get_mut(&DEVICE).expect("member").network += 1;
        let key = [0xA5; 32];
        assert_eq!(
            channels.send_update(
                &directory,
                DEVICE,
                UpdateParams {
                    generation: 9,
                    g: 13,
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                    gk: &key,
                },
                1001,
            ),
            Err(ChannelSendError::StaleMember)
        );
        assert!(channels.take_outbound().is_empty());
    }

    #[test]
    fn retire_device_discards_queued_carriers() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let _device = handshake(&mut channels, &directory);
        let key = [0xA5; 32];
        channels
            .send_update(
                &directory,
                DEVICE,
                UpdateParams {
                    generation: 9,
                    g: 13,
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                    gk: &key,
                },
                1001,
            )
            .expect("queued update");
        channels.retire_device(DEVICE);
        assert!(channels.take_outbound().is_empty());
    }

    #[test]
    fn full_event_queue_does_not_lose_verified_events_or_replay_retry() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut device = handshake(&mut channels, &directory);
        let mut state = 0x52;
        for request_id in 1..=MAX_EVENTS as u64 {
            let body = BodyHead {
                op: 1,
                generation: 9,
                request_id,
            }
            .encode(1)
            .expect("head");
            channels.on_carrier(
                &directory,
                DEVICE,
                CarrierKind::Envelope,
                &device.seal(6, &body),
                1000,
                &mut rng(&mut state),
            );
        }
        let last = BodyHead {
            op: 1,
            generation: 9,
            request_id: MAX_EVENTS as u64 + 1,
        }
        .encode(1)
        .expect("head");
        let retry = device.seal(6, &last);
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &retry,
            1000,
            &mut rng(&mut state),
        );
        for request_id in 1..=MAX_EVENTS as u64 {
            let Some(ChannelEvent::Passthrough { body, .. }) = channels.poll_event() else {
                panic!("lost event {request_id}");
            };
            assert_eq!(
                BodyHead::decode(&body, 1).expect("head").request_id,
                request_id
            );
        }
        assert!(channels.poll_event().is_none());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &retry,
            1001,
            &mut rng(&mut state),
        );
        assert!(matches!(
            channels.poll_event(),
            Some(ChannelEvent::Passthrough { .. })
        ));
    }

    #[test]
    fn malformed_r3_does_not_consume_a_valid_pending_handshake() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut state = 0x1234;
        let (r1, mut device) = FakeDevice::begin(DEVICE, dams(), 0xA001, [0x64; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1000,
            &mut rng(&mut state),
        );
        let r2 = drain_r2(&mut channels);
        let r3 = device.on_r2(&r2);
        let mut corrupt = r3.clone();
        corrupt[0] ^= 1;
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R3,
            &corrupt,
            1001,
            &mut rng(&mut state),
        );
        assert_eq!(channels.stats().pending, 1);
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R3,
            &r3,
            1002,
            &mut rng(&mut state),
        );
        assert!(matches!(
            channels.poll_event(),
            Some(ChannelEvent::ChannelReady { .. })
        ));
    }

    #[test]
    fn request_id_exhaustion_retires_before_wrap() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let _device = handshake(&mut channels, &directory);
        channels
            .channels
            .get_mut(&DEVICE)
            .expect("channel")
            .request_id = u64::MAX;
        let key = [0xA5; 32];
        assert_eq!(
            channels.send_update(
                &directory,
                DEVICE,
                UpdateParams {
                    generation: 9,
                    g: 13,
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                    gk: &key,
                },
                1001,
            ),
            Err(ChannelSendError::CounterExhausted)
        );
        assert_eq!(channels.stats().channels, 0);
    }

    #[test]
    fn zero_dams_member_cannot_start_a_channel() {
        let directory = FakeDirectory::with(DEVICE, [0; 32]);
        let mut channels = AuthorityChannels::new(config());
        let mut state = 0x23;
        let (r1, _) = FakeDevice::begin(DEVICE, [0; 32], 0xA001, [0x81; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1000,
            &mut rng(&mut state),
        );
        assert_eq!(channels.stats().pending, 0);

        let mut directory = FakeDirectory::with(DEVICE, dams());
        directory.devices.get_mut(&DEVICE).expect("member").kid = [0; 32];
        let mut channels = AuthorityChannels::new(config());
        let (r1, _) = FakeDevice::begin(DEVICE, dams(), 0xA002, [0x82; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1000,
            &mut rng(&mut state),
        );
        assert_eq!(channels.stats().pending, 0);
    }

    #[test]
    fn changed_generation_or_kid_retires_an_existing_channel() {
        let mut directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut device = handshake(&mut channels, &directory);
        let mut state = 0x19;
        let body = JoinConfirmUp {
            head: BodyHead {
                op: 1,
                generation: 9,
                request_id: 1,
            },
            cert_hash: [0x42; 32],
            boot: 1,
            current: 0,
            next: 0,
        }
        .encode()
        .expect("confirm");
        let envelope = device.seal(1, &body);
        directory
            .devices
            .get_mut(&DEVICE)
            .expect("member")
            .generation += 1;
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &envelope,
            1001,
            &mut rng(&mut state),
        );
        assert_eq!(channels.stats().channels, 0);
        assert!(matches!(
            channels.poll_event(),
            Some(ChannelEvent::ChannelLost { .. })
        ));

        let mut channels = AuthorityChannels::new(config());
        let mut directory = FakeDirectory::with(DEVICE, dams());
        let _device = handshake(&mut channels, &directory);
        directory.devices.get_mut(&DEVICE).expect("member").kid[0] ^= 1;
        let key = [0xA5; 32];
        assert_eq!(
            channels.send_update(
                &directory,
                DEVICE,
                UpdateParams {
                    generation: 9,
                    g: 13,
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                    gk: &key,
                },
                1001,
            ),
            Err(ChannelSendError::StaleMember)
        );
    }

    #[test]
    fn pending_handshake_expires_at_clock_ceiling() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut state = 0x61;
        let (r1, _) = FakeDevice::begin(DEVICE, dams(), 0xA001, [0x9A; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            u64::MAX - 5,
            &mut rng(&mut state),
        );
        assert_eq!(channels.stats().pending, 1);
        channels.tick(u64::MAX);
        assert_eq!(channels.stats().pending, 0);
    }

    #[test]
    fn body_generation_must_match_bound_member() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let mut device = handshake(&mut channels, &directory);
        let mut state = 0x97;
        let body = JoinConfirmUp {
            head: BodyHead {
                op: 1,
                generation: 10,
                request_id: 1,
            },
            cert_hash: [0x42; 32],
            boot: 1,
            current: 0,
            next: 0,
        }
        .encode()
        .expect("confirm");
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::Envelope,
            &device.seal(1, &body),
            1001,
            &mut rng(&mut state),
        );
        assert!(channels.poll_event().is_none());
        let key = [0xA5; 32];
        assert_eq!(
            channels.send_update(
                &directory,
                DEVICE,
                UpdateParams {
                    generation: 10,
                    g: 13,
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                    gk: &key,
                },
                1002,
            ),
            Err(ChannelSendError::InvalidParams)
        );
        assert!(channels.take_outbound().is_empty());
    }

    #[test]
    fn rehandshake_discards_old_channel_carriers() {
        let directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let _old = handshake(&mut channels, &directory);
        let key = [0xA5; 32];
        channels
            .send_update(
                &directory,
                DEVICE,
                UpdateParams {
                    generation: 9,
                    g: 13,
                    cause: UpdateCause::Periodic,
                    overlap_s: 60,
                    gk: &key,
                },
                1001,
            )
            .expect("old update");
        let mut state = 0x1A;
        let (r1, mut device) = FakeDevice::begin(DEVICE, dams(), 0xA002, [0xA2; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1002,
            &mut rng(&mut state),
        );
        let r2_slot = channels
            .outbound
            .iter()
            .position(|carrier| carrier.kind == CarrierKind::R2)
            .expect("R2");
        let r2 = channels.outbound.remove(r2_slot);
        let r3 = device.on_r2(&r2.bytes);
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R3,
            &r3,
            1003,
            &mut rng(&mut state),
        );
        assert!(channels.take_outbound().is_empty());
    }

    #[test]
    fn reissued_member_r1_retires_old_context() {
        let mut directory = FakeDirectory::with(DEVICE, dams());
        let mut channels = AuthorityChannels::new(config());
        let _old = handshake(&mut channels, &directory);
        let new_dams = [0xA5; 32];
        let member = directory.devices.get_mut(&DEVICE).expect("member");
        member.dams = new_dams;
        member.generation += 1;
        member.kid[0] ^= 1;
        let mut state = 0x1B;
        let (r1, _) = FakeDevice::begin(DEVICE, new_dams, 0xA002, [0xA3; 16], net());
        channels.on_carrier(
            &directory,
            DEVICE,
            CarrierKind::R1,
            &r1,
            1002,
            &mut rng(&mut state),
        );
        assert_eq!(channels.stats().channels, 0);
        assert_eq!(channels.stats().pending, 1);
    }
}
