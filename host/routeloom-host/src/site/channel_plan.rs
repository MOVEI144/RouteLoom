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
    CAP_HOST_OPS_V1, CHANNEL_PLAN_REQUIRED_MAX, HOST_OPS_SCHEMA, SUB_CHANNEL_PLAN_REPORT,
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
    /// The plan this daemon offered last: a release needs its own report.
    offered: Option<[u8; 32]>,
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
        if let Some((_, sent, action)) = self.in_flight {
            if now_mono.saturating_sub(sent) < REQUEST_TIMEOUT_MS {
                return None;
            }
            self.in_flight = None;
            self.last = Some((action, u16::MAX, 0));
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
        // The previous plan's READY count must never read as this plan's.
        self.channel_plan.report = None;
        self.channel_plan.offered = Some(signed.plan_hash);
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
        if report.result != 0 || !(1..=13).contains(&report.active_channel) {
            return Err("gateway has no usable channel plan status".into());
        }
        if !(1..=13).contains(&new_channel) || new_channel == report.active_channel {
            return Err("new_channel must differ from the active channel".into());
        }
        // ParticipantPhase 3..=6: a plan is preparing, committed, switching
        // or verifying.
        if (3..=6).contains(&report.phase) || report.cooldown_ms != 0 {
            return Err("the gateway is not ready for a new plan".into());
        }
        let switch = report
            .gateway_now_ms
            .checked_add(now_mono.saturating_sub(at))
            .and_then(|value| value.checked_add(lead_ms))
            .ok_or("gateway plan clock overflow")?;
        let expiry = switch
            .checked_add(u64::from(GUARD_MS) + VALIDITY_MS)
            .ok_or("gateway plan expiry overflow")?;
        let sequence = report
            .ledger_sequence
            .checked_add(1)
            .ok_or("gateway plan sequence exhausted")?;
        let epoch = report
            .active_epoch
            .checked_add(1)
            .ok_or("gateway channel epoch exhausted")?;
        let plan = ChannelPlan {
            network: self.id.network,
            authority: self.id.site_id,
            authority_generation: 1,
            operation_sequence: sequence,
            previous_state_hash: report.ledger_state,
            old_epoch: report.active_epoch,
            new_epoch: epoch,
            old_channel: report.active_channel,
            new_channel,
            participant_capability_mask: CAPABILITY_MASK,
            switch_reference_ms: switch,
            uncertainty_ms: UNCERTAINTY_MS,
            expiry_ms: expiry,
            guard_ms: GUARD_MS,
            protected_services_mask: 1,
            max_outage_ms: MAX_OUTAGE_MS,
            ..ChannelPlan::default()
        };
        Ok(plan)
    }

    /// Members that must answer READY before a release: every member but
    /// the plan authority (the first gateway). The gateway only knows its
    /// connected peers, so a member it cannot hear would be left behind.
    pub fn channel_plan_required(&self) -> usize {
        let authority = self.id.gateways[0];
        self.devices
            .values()
            .filter(|row| row.member && row.node != authority)
            .count()
    }

    /// Queues release of the plan the gateway currently holds, once its
    /// fresh report shows READY from every required member. A fresh
    /// gateway report also permits release after the daemon restarted.
    pub fn channel_plan_release(&mut self, now_mono: u64) -> Result<[u8; 32], String> {
        let authority = self.id.gateways[0];
        let mut required: Vec<u64> = self
            .devices
            .values()
            .filter(|row| row.member && row.node != authority)
            .map(|row| row.node)
            .collect();
        required.sort_unstable();
        if required.len() > CHANNEL_PLAN_REQUIRED_MAX {
            return Err("NOT_READY: required member set exceeds gateway capacity".into());
        }
        let report = self
            .channel_plan
            .fresh_report(now_mono)
            .ok_or("NOT_READY: read a fresh channel plan status first")?;
        if report.result != 0 || report.released || report.offered_plan == [0; 32] {
            return Err("gateway has no held channel plan".into());
        }
        if self
            .channel_plan
            .offered
            .is_some_and(|offered| offered != report.offered_plan)
        {
            return Err("NOT_READY: the gateway report is for another plan".into());
        }
        if usize::from(report.ready) < required.len() {
            return Err(format!(
                "NOT_READY: {} of {} members answered READY",
                report.ready,
                required.len()
            ));
        }
        let plan_hash = report.offered_plan;
        self.channel_plan.queue(ChannelPlanRequest::Release {
            plan_hash,
            required,
        })?;
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
        let required = self.channel_plan_required();
        format!("{{\"report\":{report},\"last\":{last},\"busy\":{busy},\"required\":{required}}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::{store::MemoryStore, testkit};

    #[test]
    fn report_counter_overflow_refuses_an_offer() {
        let mut site = testkit::authority(Box::<MemoryStore>::default(), 100);
        site.channel_plan.report = Some((
            ChannelPlanReport {
                active_channel: 1,
                gateway_now_ms: u64::MAX,
                ledger_sequence: u64::MAX,
                active_epoch: u32::MAX,
                ..ChannelPlanReport::default()
            },
            100,
        ));
        assert!(site.channel_plan_build(6, DEFAULT_LEAD_MS, 100).is_err());
    }

    #[test]
    fn gateway_report_recovers_release_after_daemon_restart() {
        let mut site = testkit::authority(Box::<MemoryStore>::default(), 100);
        let plan_hash = [0x47; 32];
        site.channel_plan.report = Some((
            ChannelPlanReport {
                result: 0,
                offered_plan: plan_hash,
                ..ChannelPlanReport::default()
            },
            100,
        ));
        assert_eq!(site.channel_plan_release(100).unwrap(), plan_hash);
    }

    #[test]
    fn release_waits_for_every_member_of_the_offered_plan() {
        let mut site = testkit::authority(Box::<MemoryStore>::default(), 100);
        for node in [testkit::GATEWAY, 0x0A, 0x0B] {
            let mut row = crate::site::store::DeviceRow::default();
            row.node = node;
            row.member = true;
            site.devices.insert(node, row);
        }
        let plan_hash = [0x47; 32];
        let report = |ready, offered_plan| ChannelPlanReport {
            result: 0,
            ready,
            offered_plan,
            ..ChannelPlanReport::default()
        };
        site.channel_plan.offered = Some(plan_hash);
        // The previous plan's report, READY from both: not this plan's.
        site.channel_plan.report = Some((report(2, [0x11; 32]), 100));
        assert!(site.channel_plan_release(100).is_err());
        // This plan, one of two members READY.
        site.channel_plan.report = Some((report(1, plan_hash), 100));
        let refused = site.channel_plan_release(100).unwrap_err();
        assert!(refused.starts_with("NOT_READY"), "{refused}");
        site.channel_plan.report = Some((report(2, plan_hash), 100));
        assert_eq!(site.channel_plan_release(100).unwrap(), plan_hash);
        let (body, _) = site.channel_plan.take_request(100).unwrap();
        assert_eq!(
            routeloom_protocol::host_ops::decode_channel_plan(&body).unwrap(),
            ChannelPlanRequest::Release {
                plan_hash,
                required: vec![0x0A, 0x0B]
            }
        );
    }

    #[test]
    fn unanswered_request_reports_timeout() {
        let mut desk = ChannelPlanDesk::default();
        assert!(!desk.busy());
        desk.queue(ChannelPlanRequest::Status).unwrap();
        assert!(desk.busy());
        let (_, action) = desk.take_request(100).unwrap();
        desk.note_sent(7, action, 100);
        assert!(desk.busy());
        assert!(desk.take_request(100 + REQUEST_TIMEOUT_MS).is_none());
        assert!(!desk.busy());
        assert_eq!(desk.last(), Some(("status", u16::MAX, 0)));
    }
}
