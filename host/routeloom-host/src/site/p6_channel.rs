//! Production P6 delivery port (G-SEC P6 PR D, 04 §7.1/§8.5/§9.1).
//!
//! [`P6ChannelTransport`] is the production [`RevocationTransport`]: it
//! seals RRS1 (type 5), RemovalNotice (type 6) and GrantRenew (type 7)
//! into the addressed member's live authority-channel context with real
//! AES-GCM, and routes the verified device reports (Applied / Get /
//! NoticeAccepted / PREPARED / APPLIED) back to the revocation and
//! cutover sinks. Tests keep injecting fakes through the same trait.
//!
//! Wire framing: every P6 payload rides behind the channel's 16-byte
//! generation head ([`send_typed`]), which the channel layer fences
//! against the bound member. The head is P5 framing, not P6 wire: the
//! revocation distributor and the cutover driver above — and the device
//! lifecycle below — only ever see the raw P6 bodies of 04 §5.2/§5.3.
//!
//! The channel table is shared: group keys (P5) seal into the same
//! per-device contexts, so the table lives in [`P6ChannelHub`] behind
//! an `Arc<Mutex<..>>` the embedder shares. The P6 transport below only
//! holds such a share; P5 PR4 maps the hub's carriers onto USB/mesh and
//! drives its GK events through [`P6ChannelHub::poll_other`] without
//! touching this file.
//!
//! Retention (04 §7.1/§8.5), all RAM-only so a restart ends every grace:
//! * a removed member's binding stays for [`P6_BINDING_GRACE_MS`] for the
//!   direct notice send and the NoticeAccepted verify — the narrow
//!   reply path outside the live-member gate, type-5 sub-3 only;
//! * a cutover keeps serving the old network for the same window so in
//!   flight COMMITs still seal, then flips the whole table to the new
//!   network. New-network handshakes wait out the grace (their R1 is
//!   answered with a hint); stragglers past the grace recover over ZT.
//!
//! [`RevocationTransport`]: super::revocation::RevocationTransport
//! [`send_typed`]:
//!     super::authority_channel::AuthorityChannels::send_typed

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use routeloom_keysched::authority::{BodyHead, BODY_HEAD};
use routeloom_protocol::authority::CarrierKind;

use super::authority_channel::{
    AuthorityChannels, AuthorityDirectory, AuthorityOutbound, ChannelConfig, ChannelEvent,
    ChannelMember,
};
use super::revocation::RevocationTransport;
use routeloom_provision::signer::fill_random;

/// How long a removed member's binding (notice send + accept verify)
/// and a retired network's bindings (COMMIT grace) stay usable after
/// they leave the live rows. RAM-only: a restart ends both.
pub const P6_BINDING_GRACE_MS: u64 = 60_000;
/// At most this many retained bindings (removals + one cutover grace);
/// past the cap the earliest-expiring entry drops first.
const RETAINED_MAX: usize = 256;
/// Minimum gap between two Get answers to the same device: the
/// legitimate Get cooldown is 60 s, so this only bites on spam.
const GET_ANSWER_GAP_MS: u64 = 5_000;

/// One verified P6 report, head stripped, ready for the revocation /
/// cutover sinks. `generation`/`network` are the channel binding the
/// report arrived over — the sinks re-fence them on the live rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P6Receipt {
    pub device: u64,
    pub generation: u32,
    pub network: u64,
    pub env_type: u8,
    pub body: Vec<u8>,
}

/// A strict type-5 report body (04 §5.2): exact length, `ver = 1`,
/// zero reserved field, nothing trailing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P6Type5 {
    Applied { rs_epoch: u32, sha: [u8; 32] },
    Get { wanted_rs_epoch: u32 },
    NoticeAccepted { rs_epoch: u32, sha: [u8; 32] },
}

/// Decodes one raw type-5 body. `None` is a malformed report: the
/// caller drops it without touching any distribution state.
pub fn decode_type5(body: &[u8]) -> Option<P6Type5> {
    if body.len() < 8 || body[0] != 1 || body[2] != 0 || body[3] != 0 {
        return None;
    }
    let field = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    match (body[1], body.len()) {
        (1, 40) => {
            let mut sha = [0_u8; 32];
            sha.copy_from_slice(&body[8..40]);
            Some(P6Type5::Applied {
                rs_epoch: field,
                sha,
            })
        }
        (2, 8) => Some(P6Type5::Get {
            wanted_rs_epoch: field,
        }),
        (3, 40) => {
            let mut sha = [0_u8; 32];
            sha.copy_from_slice(&body[8..40]);
            Some(P6Type5::NoticeAccepted {
                rs_epoch: field,
                sha,
            })
        }
        _ => None,
    }
}

struct Retained {
    member: ChannelMember,
    until_mono_ms: u64,
}

/// The shared channel table behind the P6 port (see the module docs).
/// Single-threaded logic under the embedder's mutex; every method is a
/// quick table operation, never a nested authority call.
pub struct P6ChannelHub {
    channels: Arc<Mutex<AuthorityChannels>>,
    live: BTreeMap<u64, ChannelMember>,
    retained: BTreeMap<u64, Retained>,
    pending_carriers: Vec<AuthorityOutbound>,
    pending_receipts: VecDeque<P6Receipt>,
    pending_other: VecDeque<ChannelEvent>,
    get_answered_at: BTreeMap<u64, u64>,
    site_id: u64,
    current_network: u64,
    grace_until_mono_ms: u64,
    last_mono_ms: u64,
}

impl P6ChannelHub {
    pub fn new(network: u64, site_id: u64, site_epoch: u32, rs_epoch: u32, gk_epoch: u32) -> Self {
        let channels = Arc::new(Mutex::new(AuthorityChannels::new(ChannelConfig {
            network,
            site_id,
            site_epoch,
            rs_epoch,
            gk_epoch,
        })));
        Self::with_channels(channels, network, site_id)
    }

    pub fn with_channels(
        channels: Arc<Mutex<AuthorityChannels>>,
        network: u64,
        site_id: u64,
    ) -> Self {
        Self {
            channels,
            live: BTreeMap::new(),
            retained: BTreeMap::new(),
            pending_carriers: Vec::new(),
            pending_receipts: VecDeque::new(),
            pending_other: VecDeque::new(),
            get_answered_at: BTreeMap::new(),
            site_id,
            current_network: network,
            grace_until_mono_ms: 0,
            last_mono_ms: 0,
        }
    }

    /// The network the live table currently serves.
    pub fn network(&self) -> u64 {
        self.channels
            .lock()
            .expect("authority channel poisoned")
            .network()
    }

    fn drain_channel_events(&mut self) {
        let events = {
            let mut channels = self.channels.lock().expect("authority channel poisoned");
            let mut events = Vec::new();
            while let Some(event) = channels.poll_event() {
                events.push(event);
            }
            events
        };
        for event in events {
            self.sort_event(event);
        }
    }

    fn grace_active(&self, mono_ms: u64) -> bool {
        self.grace_until_mono_ms != 0 && mono_ms < self.grace_until_mono_ms
    }

    /// Looks the binding up the way the channel fences it: during the
    /// cutover grace the retained old bindings win (new handshakes
    /// wait); otherwise live rows first, retained removals second.
    /// Expired retention never serves.
    fn lookup(&self, device: u64, mono_ms: u64) -> Option<ChannelMember> {
        lookup_binding(
            &self.live,
            &self.retained,
            self.grace_until_mono_ms,
            device,
            mono_ms,
        )
    }

    /// Syncs the live rows (called every authority tick): expires
    /// retention, retires idle channels, flips the table past the
    /// cutover grace, and advertises the current RRS/GK epochs.
    pub fn refresh(
        &mut self,
        live: &[(u64, ChannelMember)],
        current_network: u64,
        rs_epoch: u32,
        gk_epoch: u32,
        mono_ms: u64,
    ) {
        // A regressed clock cannot extend any grace: end every retention
        // rather than serve stale contexts past their window.
        if mono_ms < self.last_mono_ms {
            self.grace_until_mono_ms = 0;
            self.retained.clear();
        }
        self.last_mono_ms = mono_ms;
        self.current_network = current_network;
        self.channels
            .lock()
            .expect("authority channel poisoned")
            .tick(mono_ms);
        self.drain_channel_events();
        let fresh: BTreeMap<u64, ChannelMember> = live
            .iter()
            .map(|(node, member)| (*node, member.clone()))
            .collect();
        let disappeared: Vec<(u64, ChannelMember)> = self
            .live
            .iter()
            .filter(|(node, member)| {
                !fresh.contains_key(*node) && member.dams.iter().any(|byte| *byte != 0)
            })
            .map(|(node, member)| (*node, member.clone()))
            .collect();
        for (node, member) in disappeared {
            self.retain(node, member, mono_ms.saturating_add(P6_BINDING_GRACE_MS));
        }
        self.live = fresh;
        let expired: Vec<u64> = self
            .retained
            .iter()
            .filter(|(_, entry)| mono_ms >= entry.until_mono_ms)
            .map(|(node, _)| *node)
            .collect();
        self.retained
            .retain(|_, entry| mono_ms < entry.until_mono_ms);
        for node in expired {
            if !self.live.contains_key(&node) {
                self.channels
                    .lock()
                    .expect("authority channel poisoned")
                    .retire_device(node);
            }
        }
        if self.grace_until_mono_ms != 0 {
            if !self.grace_active(mono_ms) {
                self.grace_until_mono_ms = 0;
                self.flip(current_network, rs_epoch, gk_epoch);
            }
            // Inside the grace the old table is frozen: no flip, no
            // epoch updates — it serves the retired network only.
        } else if self.network() != current_network {
            // No grace announced (e.g. the port attached after the
            // commit): adopt the current network at once, keeping
            // only retention that is still inside its own window.
            self.flip(current_network, rs_epoch, gk_epoch);
        } else {
            self.channels
                .lock()
                .expect("authority channel poisoned")
                .set_epochs(rs_epoch, gk_epoch);
        }
    }

    fn retain(&mut self, node: u64, member: ChannelMember, until_mono_ms: u64) {
        if self.retained.len() >= RETAINED_MAX {
            // Bounded and fail-closed: drop the earliest-expiring
            // entry, never a live row or an unexpired grace.
            if let Some(victim) = self
                .retained
                .iter()
                .min_by_key(|(_, entry)| entry.until_mono_ms)
                .map(|(node, _)| *node)
            {
                self.retained.remove(&victim);
            }
        }
        self.retained.insert(
            node,
            Retained {
                member,
                until_mono_ms,
            },
        );
    }

    /// Starts the post-commit COMMIT grace: the table keeps serving
    /// `old_network` for [`P6_BINDING_GRACE_MS`], then flips. Calls
    /// for any other network are ignored (a stale or replayed note).
    pub fn note_cutover(&mut self, old_network: u64, mono_ms: u64) {
        if old_network == 0 || old_network != self.network() {
            return;
        }
        let grace: Vec<(u64, ChannelMember)> = self
            .live
            .iter()
            .filter(|(_, member)| member.network == old_network)
            .map(|(node, member)| (*node, member.clone()))
            .collect();
        for (node, member) in grace {
            self.retain(node, member, mono_ms.saturating_add(P6_BINDING_GRACE_MS));
        }
        self.live.clear();
        self.grace_until_mono_ms = mono_ms.saturating_add(P6_BINDING_GRACE_MS);
    }

    /// Replaces the channel table with one serving `network`, carrying
    /// over queued carriers and unpolled P6 receipts. Pending
    /// handshakes and idle channels of the retired table drop: their
    /// devices re-handshake (or recover over ZT) on the new network.
    fn flip(&mut self, network: u64, rs_epoch: u32, gk_epoch: u32) {
        self.pending_carriers.extend(
            self.channels
                .lock()
                .expect("authority channel poisoned")
                .take_outbound(),
        );
        self.drain_channel_events();
        *self.channels.lock().expect("authority channel poisoned") =
            AuthorityChannels::new(ChannelConfig {
                network,
                site_id: self.site_id,
                site_epoch: (network >> 32) as u32,
                rs_epoch,
                gk_epoch,
            });
    }

    /// Feeds one inbound carrier (USB 0x64 / mesh, reassembled by the
    /// P5 PR4 mapping) into the table.
    pub fn push_carrier(&mut self, device: u64, kind: CarrierKind, bytes: &[u8], mono_ms: u64) {
        // A removed member may finish the notice exchange on its existing
        // context, but cannot create a new one during the retention window.
        if (kind == CarrierKind::R3 && !self.live.contains_key(&device))
            || (kind == CarrierKind::R1
                && self.retained.contains_key(&device)
                && !self.live.contains_key(&device))
        {
            return;
        }
        self.last_mono_ms = mono_ms;
        let directory = HubDirectory {
            live: &self.live,
            retained: &self.retained,
            grace_until_mono_ms: self.grace_until_mono_ms,
            now: mono_ms,
        };
        let mut rng = |buf: &mut [u8]| fill_random(buf).is_ok();
        self.channels
            .lock()
            .expect("authority channel poisoned")
            .on_carrier(&directory, device, kind, bytes, mono_ms, &mut rng);
        self.drain_channel_events();
    }

    /// Sorts one channel event: type-5/7 P6 reports become receipts,
    /// everything else waits for the P5 GK pump.
    fn sort_event(&mut self, event: ChannelEvent) {
        let device = match &event {
            ChannelEvent::ChannelReady { device }
            | ChannelEvent::ChannelLost { device, .. }
            | ChannelEvent::JoinConfirm { device, .. }
            | ChannelEvent::Pull { device, .. }
            | ChannelEvent::UpdateAck { device, .. }
            | ChannelEvent::ActivateAck { device, .. }
            | ChannelEvent::Passthrough { device, .. } => *device,
        };
        if !self.live.contains_key(&device) {
            if let ChannelEvent::Passthrough {
                env_type: 5, body, ..
            } = &event
            {
                if body.len() >= BODY_HEAD
                    && matches!(
                        decode_type5(&body[BODY_HEAD..]),
                        Some(P6Type5::NoticeAccepted { .. })
                    )
                {
                    // The common receipt parser below still checks the
                    // retained binding and authenticated generation.
                } else {
                    return;
                }
            } else {
                return;
            }
        }
        let (device, env_type, body) = match &event {
            ChannelEvent::Passthrough {
                device,
                env_type,
                body,
            } if matches!(env_type, 5 | 7) => (*device, *env_type, body.clone()),
            _ => {
                if self.pending_other.len() < 64 {
                    self.pending_other.push_back(event);
                }
                return;
            }
        };
        let receipt = (|| {
            if body.len() < BODY_HEAD + 1 {
                return None;
            }
            let head = BodyHead::decode(&body[..BODY_HEAD], body[1]).ok()?;
            let binding = self.lookup(device, self.last_mono_ms)?;
            if binding.network != self.network()
                || head.op != 2
                || head.generation != binding.generation
            {
                return None;
            }
            Some(P6Receipt {
                device,
                generation: head.generation,
                network: binding.network,
                env_type,
                body: body[BODY_HEAD..].to_vec(),
            })
        })();
        match receipt {
            Some(receipt) => {
                if self.pending_receipts.len() < 64 {
                    self.pending_receipts.push_back(receipt);
                }
            }
            None => {
                // A well-AEAD'd envelope the P6 sink cannot use (torn
                // head, retired binding): counted upstream as a
                // rejected report, never applied.
                if self.pending_other.len() < 64 {
                    self.pending_other.push_back(event);
                }
            }
        }
    }

    /// Takes the verified P6 reports queued since the last call.
    pub fn poll_receipts(&mut self) -> Vec<P6Receipt> {
        self.pending_receipts.drain(..).collect()
    }

    /// Takes the non-P6 channel events (JoinConfirm / Pull / ACKs /
    /// ChannelReady / ChannelLost / type-8): the P5 GK pump drains
    /// these; the P6 port never consumes them.
    pub fn poll_other(&mut self) -> Vec<ChannelEvent> {
        self.pending_other.drain(..).collect()
    }

    /// Takes every queued outbound carrier (R2 / sealed envelopes) for
    /// the P5 PR4 USB/mesh mapping.
    pub fn take_carriers(&mut self) -> Vec<AuthorityOutbound> {
        let mut out = std::mem::take(&mut self.pending_carriers);
        out.extend(
            self.channels
                .lock()
                .expect("authority channel poisoned")
                .take_outbound(),
        );
        out
    }

    /// Notes a Get answer for the per-device spam gap. Returns false
    /// when the device was answered too recently (the answer drops).
    pub fn note_get_answer(&mut self, device: u64, mono_ms: u64) -> bool {
        if self
            .get_answered_at
            .get(&device)
            .is_some_and(|at| mono_ms.saturating_sub(*at) < GET_ANSWER_GAP_MS)
        {
            return false;
        }
        if self.get_answered_at.len() >= 128 {
            self.get_answered_at.pop_first();
        }
        self.get_answered_at.insert(device, mono_ms);
        true
    }

    fn send_on(
        &mut self,
        device: u64,
        env_type: u8,
        network: u64,
        tail: &[u8],
        live_only: bool,
        mono_ms: u64,
    ) -> bool {
        // The seal network must be the table network. During the
        // COMMIT grace the authority already moved on: only the old
        // network COMMIT seals; everything else waits out the grace,
        // honestly unknown, instead of sealing under the wrong
        // context.
        if network != self.network() {
            return false;
        }
        let grace_commit =
            env_type == 7 && network != self.current_network && self.grace_active(mono_ms);
        if network != self.current_network && !grace_commit {
            return false;
        }
        let binding = if live_only {
            match self.live.get(&device) {
                Some(binding) => binding.clone(),
                None => return false,
            }
        } else {
            match self.lookup(device, mono_ms) {
                Some(binding) => binding,
                None => return false,
            }
        };
        if binding.network != network {
            return false;
        }
        if live_only && !binding.member {
            return false;
        }
        if !binding.member && env_type != 6 {
            // Only the direct notice may ride a retained (removed)
            // binding, and only inside its window.
            return false;
        }
        let directory = HubDirectory {
            live: &self.live,
            retained: &self.retained,
            grace_until_mono_ms: self.grace_until_mono_ms,
            now: mono_ms,
        };
        self.channels
            .lock()
            .expect("authority channel poisoned")
            .send_typed(
                &directory,
                device,
                env_type,
                binding.generation,
                tail,
                mono_ms,
            )
            .is_ok()
    }

    /// True when a notice to `node` on `network` could still seal: a
    /// live or retained binding exists *and* the device holds an
    /// established channel. When false the distributor marks the
    /// notice `unreachable` instead of queueing a send that cannot
    /// seal (04 §7.1: no existing context) and stalling the shared
    /// outbox behind it.
    pub fn notice_sealable(&self, node: u64, network: u64, mono_ms: u64) -> bool {
        let channels = self.channels.lock().expect("authority channel poisoned");
        if network != channels.network() || !channels.has_channel(node) {
            return false;
        }
        self.lookup(node, mono_ms)
            .is_some_and(|binding| binding.network == network)
    }

    /// Seals an RRS1 object for a live member of the current network.
    pub fn send_rrs(&mut self, node: u64, object: &[u8], mono_ms: u64) -> bool {
        self.send_on(node, 5, self.current_network, object, true, mono_ms)
    }

    /// Seals a RemovalNotice, including to a retained removed binding.
    pub fn send_notice(&mut self, node: u64, network: u64, notice: &[u8], mono_ms: u64) -> bool {
        self.send_on(node, 6, network, notice, false, mono_ms)
    }

    /// Captures a notice while the member row and its channel are still
    /// current. The ciphertext is returned to the revoke transaction and
    /// cannot enter the transport outbox until that transaction commits.
    pub fn preseal_notice(
        &mut self,
        node: u64,
        network: u64,
        notice: &[u8],
        mono_ms: u64,
    ) -> Option<Vec<u8>> {
        if network != self.current_network || network != self.network() {
            return None;
        }
        let binding = self.live.get(&node)?.clone();
        if !binding.member || binding.network != network {
            return None;
        }
        let directory = HubDirectory {
            live: &self.live,
            retained: &self.retained,
            grace_until_mono_ms: self.grace_until_mono_ms,
            now: mono_ms,
        };
        self.channels
            .lock()
            .expect("authority channel poisoned")
            .seal_typed_detached(&directory, node, 6, binding.generation, notice, mono_ms)
            .ok()
            .map(|outbound| outbound.bytes)
    }

    pub fn send_presealed_notice(&mut self, node: u64, sealed: &[u8]) -> bool {
        if sealed.is_empty() || sealed.len() > 2048 || self.pending_carriers.len() >= 64 {
            return false;
        }
        self.pending_carriers.push(AuthorityOutbound {
            device: node,
            kind: CarrierKind::Envelope,
            bytes: sealed.to_vec(),
        });
        true
    }

    /// Seals a GrantRenew plaintext (PREPARE pre-commit, COMMIT on the
    /// old network during the grace).
    pub fn send_grant(&mut self, node: u64, network: u64, plaintext: &[u8], mono_ms: u64) -> bool {
        let live_only = network == self.current_network;
        self.send_on(node, 7, network, plaintext, live_only, mono_ms)
    }
}

impl std::fmt::Debug for P6ChannelHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P6ChannelHub")
            .field("network", &format_args!("{:016x}", self.network()))
            .field("live", &self.live.len())
            .field("retained", &self.retained.len())
            .field("grace", &self.grace_until_mono_ms)
            .finish()
    }
}

/// The binding lookup shared by the hub and its channel directory:
/// during the cutover grace the retained old bindings win, otherwise
/// live rows first, retained removals second. Expired retention never
/// serves.
fn lookup_binding(
    live: &BTreeMap<u64, ChannelMember>,
    retained: &BTreeMap<u64, Retained>,
    grace_until_mono_ms: u64,
    device: u64,
    mono_ms: u64,
) -> Option<ChannelMember> {
    let retained_hit = retained
        .get(&device)
        .filter(|entry| mono_ms < entry.until_mono_ms)
        .map(|entry| entry.member.clone());
    if grace_until_mono_ms != 0 && mono_ms < grace_until_mono_ms {
        return retained_hit;
    }
    if let Some(member) = live.get(&device) {
        return Some(member.clone());
    }
    retained_hit
}

struct HubDirectory<'a> {
    live: &'a BTreeMap<u64, ChannelMember>,
    retained: &'a BTreeMap<u64, Retained>,
    grace_until_mono_ms: u64,
    now: u64,
}

impl AuthorityDirectory for HubDirectory<'_> {
    fn lookup(&self, device: u64) -> Option<ChannelMember> {
        lookup_binding(
            self.live,
            self.retained,
            self.grace_until_mono_ms,
            device,
            self.now,
        )
    }
}

/// The production [`RevocationTransport`]: a share of a [`P6ChannelHub`].
/// All trait calls lock the hub briefly; no call blocks on radio/USB
/// and none calls back into the authority.
pub struct P6ChannelTransport {
    hub: Arc<Mutex<P6ChannelHub>>,
    delivery_attached: bool,
    /// Last monotonic tick seen (send gating); refreshed by
    /// `refresh_p6_bindings` every authority tick.
    mono_ms: u64,
}

impl P6ChannelTransport {
    /// Shares `hub` (created by the embedder with the site's current
    /// network/epochs, shared with the P5 carrier mapping).
    pub fn share(hub: &Arc<Mutex<P6ChannelHub>>) -> Self {
        Self {
            hub: Arc::clone(hub),
            delivery_attached: true,
            mono_ms: 0,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, P6ChannelHub> {
        self.hub.lock().expect("p6 channel hub poisoned")
    }
}

impl RevocationTransport for P6ChannelTransport {
    fn send_rrs(&mut self, node: u64, object: &[u8]) -> bool {
        if !self.delivery_attached {
            return false;
        }
        self.lock().send_rrs(node, object, self.mono_ms)
    }

    fn send_notice(&mut self, node: u64, network: u64, notice: &[u8]) -> bool {
        if !self.delivery_attached {
            return false;
        }
        self.lock().send_notice(node, network, notice, self.mono_ms)
    }

    fn preseal_notice(&mut self, node: u64, network: u64, notice: &[u8]) -> Option<Vec<u8>> {
        self.lock()
            .preseal_notice(node, network, notice, self.mono_ms)
    }

    fn send_presealed_notice(&mut self, node: u64, sealed: &[u8]) -> bool {
        if !self.delivery_attached {
            return false;
        }
        self.lock().send_presealed_notice(node, sealed)
    }

    fn send_grant(&mut self, node: u64, network: u64, plaintext: &[u8]) -> bool {
        if !self.delivery_attached {
            return false;
        }
        self.lock()
            .send_grant(node, network, plaintext, self.mono_ms)
    }

    fn carries_notice(&self) -> bool {
        true
    }

    fn carries_grant(&self) -> bool {
        true
    }

    fn p6_ready(&self) -> bool {
        true
    }

    fn set_delivery_attached(&mut self, attached: bool) {
        self.delivery_attached = attached;
    }

    fn push_carrier(&mut self, device: u64, kind: CarrierKind, bytes: &[u8], now_ms: u64) {
        self.lock().push_carrier(device, kind, bytes, now_ms);
    }

    fn poll_p6_receipts(&mut self) -> Vec<P6Receipt> {
        self.lock().poll_receipts()
    }

    fn poll_channel_events(&mut self) -> Vec<ChannelEvent> {
        self.lock().poll_other()
    }

    fn take_p6_carriers(&mut self) -> Vec<AuthorityOutbound> {
        self.lock().take_carriers()
    }

    fn refresh_p6_bindings(
        &mut self,
        live: &[(u64, ChannelMember)],
        current_network: u64,
        rs_epoch: u32,
        gk_epoch: u32,
        mono_ms: u64,
    ) {
        self.mono_ms = mono_ms;
        self.lock()
            .refresh(live, current_network, rs_epoch, gk_epoch, mono_ms);
    }

    fn note_p6_cutover(&mut self, old_network: u64, mono_ms: u64) {
        self.mono_ms = mono_ms;
        self.lock().note_cutover(old_network, mono_ms);
    }

    fn note_p6_get_answer(&mut self, device: u64, mono_ms: u64) -> bool {
        self.lock().note_get_answer(device, mono_ms)
    }

    fn notice_sealable(&self, node: u64, network: u64, mono_ms: u64) -> bool {
        self.lock().notice_sealable(node, network, mono_ms)
    }
}
