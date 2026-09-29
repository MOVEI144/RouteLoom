//! Manual channel plan dispatch (V2-08, issue #5 manual; channel_plan_v1).
//!
//! The Site Authority builds the next plan against the gateway's newest
//! 0x69 report — its ledger head (sequence, state hash), active epoch and
//! channel, and its monotonic clock, which is the plan's time domain —
//! signs it with the SAK and queues it for the site lane as HostOps 0x68.
//! The gateway verifies every plan with the adopted site's SAK and
//! distributes it; releasing the commit is a separate, explicit request
//! once the members answered READY. One request is in flight at a time;
//! nothing here is persisted (the gateway's ledger is the durable state).

use routeloom_protocol::host_ops::{
    encode_channel_plan, ChannelPlanReport, ChannelPlanRequest, CAP_CHANNEL_PLAN_V1,
    CAP_HOST_OPS_V1, HOST_OPS_SCHEMA, SUB_CHANNEL_PLAN_REPORT,
};
use routeloom_provision::sdkv1::channel_plan::{ChannelPlan, SignedChannelPlan};

use super::SiteAuthority;
use crate::receive_log::hex_lower;

/// A plan is built only from a report at most this old.
pub const REPORT_MAX_AGE_MS: u64 = 5_000;
/// A request the gateway never answered frees the desk after this.
pub const REQUEST_TIMEOUT_MS: u64 = 5_000;
/// Default offer-to-switch lead: a member's commit lead (7 s with the
/// default measured bounds) plus the 5 s TimeSync period that arms its
/// clock, with room for the operator's release.
pub const DEFAULT_LEAD_MS: u64 = 30_000;
pub const LEAD_MIN_MS: u64 = 10_000;
pub const LEAD_MAX_MS: u64 = 600_000;
/// Plan timing: clock uncertainty, the guard around the switch (covers a
/// measured switch bound up to 210 ms: 4 x 10 + 210), the validity window
/// past the guard and the service outage budget.
const UNCERTAINTY_MS: u32 = 10;
const GUARD_MS: u32 = 250;
const VALIDITY_MS: u64 = 120_000;
const MAX_OUTAGE_MS: u32 = 500;
/// The device's kChannelMaskAll24 (channels 1..=13).
const CAPABILITY_MASK: u32 = 0x3FFF;

/// The 0x69 sub of an inner body, if any (the site lane's router test).
pub fn channel_plan_sub(inner: &[u8]) -> Option<u8> {
    (inner.len() >= 2 && inner[0] == HOST_OPS_SCHEMA && inner[1] == SUB_CHANNEL_PLAN_REPORT)
        .then_some(SUB_CHANNEL_PLAN_REPORT)
}

/// The family rides the HostOps carrier: both bits must be advertised.
pub fn channel_plan_capable(capability: u32) -> bool {
    capability & CAP_CHANNEL_PLAN_V1 != 0 && capability & CAP_HOST_OPS_V1 != 0
}

#[derive(Default)]
pub struct ChannelPlanDesk {
    queued: Option<ChannelPlanRequest>,
    in_flight: Option<(u64, u64, &'static str)>,
    report: Option<(ChannelPlanReport, u64)>,
    /// (action, result, detail) of the newest answered request.
    last: Option<(&'static str, u16, u8)>,
    offered: Option<SignedChannelPlan>,
}

fn action_name(request: &ChannelPlanRequest) -> &'static str {
    match request {
        ChannelPlanRequest::Status => "status",
        ChannelPlanRequest::Offer { .. } => "offer",
        ChannelPlanRequest::Release { .. } => "release",
    }
}

impl ChannelPlanDesk {
    pub(crate) fn queue(&mut self, request: ChannelPlanRequest) -> Result<(), String> {
        if self.queued.is_some() || self.in_flight.is_some() {
            return Err("a channel plan request is already in flight".into());
        }
        self.queued = Some(request);
        Ok(())
    }

    /// The next 0x68 inner body for the lane, if one is queued and none is
    /// in flight. A request the gateway never answered times out here.
    pub fn take_request(&mut self, now_mono: u64) -> Option<(Vec<u8>, &'static str)> {
        if let Some((_, sent, _)) = self.in_flight {
            if now_mono.saturating_sub(sent) < REQUEST_TIMEOUT_MS {
                return None;
            }
            self.in_flight = None;
        }
        let request = self.queued.take()?;
        let action = action_name(&request);
        encode_channel_plan(&request)
            .ok()
            .map(|body| (body, action))
    }

    pub fn note_sent(&mut self, request: u64, action: &'static str, now_mono: u64) {
        self.in_flight = Some((request, now_mono, action));
    }

    /// No capable session: the queued request cannot leave.
    pub fn drop_unattached(&mut self) {
        if let Some(request) = self.queued.take() {
            self.last = Some((action_name(&request), u16::MAX, 0));
        }
        self.in_flight = None;
    }

    /// A 0x69 for our request id; strays are ignored.
    pub fn on_report(&mut self, request: u64, report: ChannelPlanReport, now_mono: u64) -> bool {
        match self.in_flight {
            Some((id, _, action)) if id == request => {
                self.in_flight = None;
                self.last = Some((action, report.result, report.detail));
                self.report = Some((report, now_mono));
                true
            }
            _ => false,
        }
    }

    pub fn busy(&self) -> bool {
        self.queued.is_some() || self.in_flight.is_some()
    }

    /// (action, result, detail) of the newest answered request.
    pub fn last(&self) -> Option<(&'static str, u16, u8)> {
        self.last
    }

    pub fn fresh_report(&self, now_mono: u64) -> Option<&ChannelPlanReport> {
        self.report
            .as_ref()
            .filter(|(_, at)| now_mono.saturating_sub(*at) <= REPORT_MAX_AGE_MS)
            .map(|(report, _)| report)
    }
}

impl SiteAuthority {
    /// Queues a status read of the gateway's plan authority.
    pub fn channel_plan_refresh(&mut self) -> Result<(), String> {
        self.channel_plan.queue(ChannelPlanRequest::Status)
    }

    /// Builds the next plan from the gateway's fresh report (its ledger
    /// head, active channel and epoch, and clock), signs it with the SAK
    /// and queues the offer. The switch lands `lead_ms` after now on the
    /// gateway's clock.
    pub fn channel_plan_offer(
        &mut self,
        new_channel: u8,
        lead_ms: u64,
        now_mono: u64,
    ) -> Result<SignedChannelPlan, String> {
        let plan = self.channel_plan_build(new_channel, lead_ms, now_mono)?;
        let signed = super::sign_plan(&plan, self.sak.as_ref()).map_err(|e| e.to_string())?;
        self.channel_plan.queue(ChannelPlanRequest::Offer {
            blob: signed.blob.clone(),
            commit_signature: signed.commit_signature,
        })?;
        self.channel_plan.offered = Some(signed.clone());
        Ok(signed)
    }

    /// The next plan on the gateway's ledger head, unsigned.
    pub fn channel_plan_build(
        &self,
        new_channel: u8,
        lead_ms: u64,
        now_mono: u64,
    ) -> Result<ChannelPlan, String> {
        if !(LEAD_MIN_MS..=LEAD_MAX_MS).contains(&lead_ms) {
            return Err("lead_ms out of range".into());
        }
        let (report, at) = self
            .channel_plan
            .report
            .clone()
            .filter(|(_, at)| now_mono.saturating_sub(*at) <= REPORT_MAX_AGE_MS)
            .ok_or("no fresh gateway report: read the channel plan status first")?;
        // ParticipantPhase 3..=6: a plan is preparing, committed, switching
        // or verifying.
        if (3..=6).contains(&report.phase) || report.cooldown_ms != 0 {
            return Err("the gateway is not ready for a new plan".into());
        }
        let switch = report.gateway_now_ms + now_mono.saturating_sub(at) + lead_ms;
        let plan = ChannelPlan {
            network: self.id.network,
            authority: self.id.site_id,
            authority_generation: 1,
            operation_sequence: report.ledger_sequence + 1,
            previous_state_hash: report.ledger_state,
            old_epoch: report.active_epoch,
            new_epoch: report.active_epoch + 1,
            old_channel: report.active_channel,
            new_channel,
            participant_capability_mask: CAPABILITY_MASK,
            switch_reference_ms: switch,
            uncertainty_ms: UNCERTAINTY_MS,
            expiry_ms: switch + u64::from(GUARD_MS) + VALIDITY_MS,
            guard_ms: GUARD_MS,
            protected_services_mask: 1,
            max_outage_ms: MAX_OUTAGE_MS,
            ..ChannelPlan::default()
        };
        Ok(plan)
    }

    /// Queues the commit release of the plan this authority offered.
    pub fn channel_plan_release(&mut self) -> Result<[u8; 32], String> {
        let plan_hash = self
            .channel_plan
            .offered
            .as_ref()
            .map(|signed| signed.plan_hash)
            .ok_or("no offered channel plan")?;
        self.channel_plan
            .queue(ChannelPlanRequest::Release { plan_hash })?;
        Ok(plan_hash)
    }

    /// `site.channel_plan.status` body: the newest gateway report and the
    /// outcome of the newest request.
    pub fn channel_plan_json(&self, now_mono: u64) -> String {
        let report = self.channel_plan.report.as_ref().map_or_else(
            || "null".to_string(),
            |(r, at)| {
                format!(
                    "{{\"age_ms\":{},\"phase\":{},\"active_channel\":{},\"active_epoch\":{},\"ready\":{},\"released\":{},\"cooldown_ms\":{},\"gateway_now_ms\":{},\"ledger_sequence\":{},\"offered_plan_hex\":\"{}\"}}",
                    now_mono.saturating_sub(*at),
                    r.phase,
                    r.active_channel,
                    r.active_epoch,
                    r.ready,
                    r.released,
                    r.cooldown_ms,
                    r.gateway_now_ms,
                    r.ledger_sequence,
                    hex_lower(&r.offered_plan),
                )
            },
        );
        let last = self.channel_plan.last.map_or_else(
            || "null".to_string(),
            |(action, result, detail)| {
                let result = match result {
                    0 => "ok",
                    1 => "busy",
                    3 => "denied",
                    4 => "unsupported",
                    5 => "invalid",
                    u16::MAX => "gateway_unavailable",
                    _ => "indeterminate",
                };
                format!("{{\"action\":\"{action}\",\"result\":\"{result}\",\"detail\":{detail}}}")
            },
        );
        let busy = self.channel_plan.queued.is_some() || self.channel_plan.in_flight.is_some();
        format!("{{\"report\":{report},\"last\":{last},\"busy\":{busy}}}")
    }
}
