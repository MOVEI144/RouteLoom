//! ProxyPolicySet distribution (#176, docs/design/sdk-v1/07 §2.1).
//!
//! `join.policy.set` mints `policy_generation`; this driver sends the
//! policy (authority envelope type 9) to every live member holding a proxy
//! role (Relay or Gateway) over its authority channel until that member
//! acknowledges the generation durable, and keeps the acknowledgements in
//! the site store (`policy_acks`). No lease: a proxy offline keeps its last
//! applied open/closed policy and is sent the current one when its channel returns.
//! Expected-device marks expire unless renewed over the authority channel.
//! Only an acknowledged generation counts; a sent but unanswered policy is
//! pending, a proxy without a channel is unknown.

use routeloom_keysched::authority::{
    ProxyPolicyAck, ProxyPolicySet, PROXY_POLICY_APPLIED, PROXY_POLICY_STALE,
};

use super::records::{h16, ROLE_GATEWAY, ROLE_RELAY};
use super::revocation::DISTRIBUTION_BACKOFF_S;
use super::store::Batch;
use super::SiteAuthority;

/// Private installation marks, bounded by the existing 64-byte policy TLV.
#[derive(Default, Eq, PartialEq)]
pub struct ExpectedJoins {
    pub marks: [[u8; 16]; 3],
    pub count: u8,
    pub ttl_s: u32,
}

impl std::fmt::Debug for ExpectedJoins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpectedJoins")
            .field("count", &self.count)
            .field("ttl_s", &self.ttl_s)
            .finish()
    }
}

impl Drop for ExpectedJoins {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.marks.zeroize();
    }
}

impl ExpectedJoins {
    pub(super) fn snapshot(&self) -> Self {
        Self {
            marks: self.marks,
            count: self.count,
            ttl_s: self.ttl_s,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.count > 3 || self.ttl_s > 86400 || (self.count != 0 && self.ttl_s == 0) {
            return Err("expected_devices: at most 3 marks, ttl 1..=86400 seconds");
        }
        for i in 0..usize::from(self.count) {
            if self.marks[i] == [0; 16] || self.marks[..i].contains(&self.marks[i]) {
                return Err("expected_devices: zero or duplicate mark");
            }
        }
        if self.marks[usize::from(self.count)..]
            .iter()
            .any(|mark| *mark != [0; 16])
        {
            return Err("expected_devices: unused marks must be zero");
        }
        Ok(())
    }

    pub fn tlv(&self) -> Vec<u8> {
        if self.ttl_s == 0 {
            return Vec::new();
        }
        let mut out = vec![0x18, 6 + 16 * self.count, 1, self.count];
        out.extend_from_slice(&self.ttl_s.to_be_bytes());
        for mark in self.marks.iter().take(usize::from(self.count)) {
            out.extend_from_slice(mark);
        }
        out
    }

    pub fn decode(tlv: &[u8]) -> Option<Self> {
        if tlv.is_empty() {
            return Some(Self::default());
        }
        if tlv.len() < 8
            || tlv[0] != 0x18
            || usize::from(tlv[1]) != tlv.len() - 2
            || tlv[2] != 1
            || tlv[3] > 3
            || tlv.len() != 8 + 16 * usize::from(tlv[3])
        {
            return None;
        }
        let mut out = Self {
            count: tlv[3],
            ttl_s: u32::from_be_bytes(tlv[4..8].try_into().ok()?),
            ..Self::default()
        };
        if out.ttl_s == 0 {
            return None;
        }
        for (i, mark) in tlv[8..].chunks_exact(16).enumerate() {
            out.marks[i].copy_from_slice(mark);
        }
        out.validate().ok()?;
        Some(out)
    }
}

/// Resend spacing while a proxy has not acknowledged the current policy.
const POLICY_RESEND_MS: u64 = 5_000;
/// Policy sends per tick (bounded airtime; the resend spacing paces each proxy).
const POLICY_SENDS_PER_TICK: usize = 4;

/// Convergence of the current policy generation over the proxies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyDistribution {
    pub proxies: usize,
    pub applied: usize,
    pub pending: usize,
    pub unknown: usize,
    /// Lowest generation among proxies that acknowledged any (`None`
    /// before the first acknowledgement).
    pub distributed: Option<u32>,
}

fn is_proxy(role: u8) -> bool {
    role == ROLE_RELAY || role == ROLE_GATEWAY
}

impl SiteAuthority {
    /// Sends the current policy to due proxies (called from the tick).
    pub(super) fn tick_policy(&mut self, now_ms: u64) {
        let generation = self.policy.policy_generation;
        if generation == 0 {
            return; // never set: every proxy runs the default (open)
        }
        if !self
            .rrs_transport
            .as_ref()
            .is_some_and(|transport| transport.p6_ready())
        {
            return;
        }
        let mut set = ProxyPolicySet {
            generation,
            zero_touch_open: self.policy.zero_touch_open,
            tlv: self.policy.expected.tlv(),
        };
        let encoded = set.encode();
        use zeroize::Zeroize;
        set.tlv.zeroize();
        let Ok(tail) = encoded else {
            return;
        };
        let tail = zeroize::Zeroizing::new(tail);
        let due: Vec<u64> = self
            .devices
            .values()
            .filter(|row| row.member && is_proxy(row.role))
            .filter(|row| {
                self.policy.expected.ttl_s != 0
                    || self.policy_applied.get(&row.node).copied().unwrap_or(0) < generation
            })
            .filter(|row| {
                self.policy_retry
                    .get(&row.node)
                    .is_none_or(|(at, _)| *at <= now_ms)
            })
            .map(|row| row.node)
            .take(POLICY_SENDS_PER_TICK)
            .collect();
        for node in due {
            let Some(transport) = self.rrs_transport.as_mut() else {
                return;
            };
            // A dormant proxy holds no channel to seal into: the hint
            // re-opens it (a Ready device ignores it).
            transport.send_wake(node);
            let sent = transport.send_policy(node, &tail);
            let attempts = self.policy_retry.get(&node).map_or(0, |(_, n)| *n);
            let wait = if sent {
                if self.policy_applied.get(&node).copied() == Some(generation)
                    && self.policy.expected.ttl_s != 0
                {
                    (u64::from(self.policy.expected.ttl_s) * 500).max(1)
                } else {
                    POLICY_RESEND_MS
                }
            } else {
                let level = (attempts as usize).min(DISTRIBUTION_BACKOFF_S.len() - 1);
                DISTRIBUTION_BACKOFF_S[level].saturating_mul(1000)
            };
            self.policy_retry.insert(
                node,
                (now_ms.saturating_add(wait), attempts.saturating_add(1)),
            );
        }
    }

    /// A verified type-9 report from `device` over its channel binding
    /// (`generation` = the assignment generation the channel is bound to).
    pub(super) fn handle_policy_ack(
        &mut self,
        device: u64,
        generation: u32,
        body: &[u8],
        now_ms: u64,
    ) {
        let live = self
            .devices
            .get(&device)
            .is_some_and(|row| row.member && row.generation == generation);
        let Ok(ack) = ProxyPolicyAck::decode(body) else {
            return;
        };
        if !live {
            return;
        }
        if ack.status != PROXY_POLICY_APPLIED && ack.status != PROXY_POLICY_STALE {
            // Conflict or storage failure: the proxy kept its stored
            // policy; the resend spacing retries.
            self.event(
                now_ms,
                format!(
                    "\"kind\":\"policy.refused\",\"device_id\":\"{}\",\"status\":{},\"policy_generation\":{}",
                    h16(device),
                    ack.status,
                    ack.generation
                ),
            );
            return;
        }
        if ack.generation == 0 || ack.generation > self.policy.policy_generation {
            return;
        }
        if ack.generation > self.policy_applied.get(&device).copied().unwrap_or(0) {
            if let Err(error) = self.store.commit(&Batch {
                policy_acks: vec![(device, ack.generation)],
                ..Batch::default()
            }) {
                self.store_error(now_ms, &error);
                return;
            }
            self.policy_applied.insert(device, ack.generation);
            self.event(
                now_ms,
                format!(
                    "\"kind\":\"policy.applied\",\"device_id\":\"{}\",\"policy_generation\":{}",
                    h16(device),
                    ack.generation
                ),
            );
        }
        if ack.generation >= self.policy.policy_generation {
            if self.policy.expected.ttl_s == 0 {
                self.policy_retry.remove(&device);
            } else {
                let wait = (u64::from(self.policy.expected.ttl_s) * 500).max(1);
                self.policy_retry
                    .insert(device, (self.join_mono_ms.saturating_add(wait), 0));
            }
        }
    }

    /// Applied / pending / unknown over the live proxies for `join.policy.get`
    /// and `site.status`.
    pub fn policy_distribution(&self) -> PolicyDistribution {
        let generation = self.policy.policy_generation;
        let channels = self.channels.lock().expect("authority channel poisoned");
        let mut out = PolicyDistribution::default();
        for row in self
            .devices
            .values()
            .filter(|row| row.member && is_proxy(row.role))
        {
            out.proxies += 1;
            let applied = self.policy_applied.get(&row.node).copied();
            if let Some(acked) = applied {
                out.distributed = Some(out.distributed.map_or(acked, |low| low.min(acked)));
            }
            if applied.unwrap_or(0) >= generation {
                out.applied += 1;
            } else if channels.has_channel(row.node) {
                out.pending += 1;
            } else {
                out.unknown += 1;
            }
        }
        out
    }
}
