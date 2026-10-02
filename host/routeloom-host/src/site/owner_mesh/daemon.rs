//! G7: the production daemon dispatch and receive paths on the mesh clock.

use super::*;
use crate::send_store::OperationStore;
use crate::{api1, dispatch, send_store};

pub(super) struct MeshDaemon {
    pub(super) state: State,
    dispatcher: dispatch::Dispatcher,
}

impl MeshDaemon {
    pub(super) fn new(now: u64) -> Self {
        let acl = Acl::parse(
            r#"{"principals":{"501":{"networks":{"*":["SEND","READ_OPERATION","READ_PAYLOAD"]}}}}"#,
        )
        .unwrap();
        let state = State {
            acl,
            rate_limiter: Mutex::new(send_store::AdmissionLimiter::with_profile(
                send_store::AdmissionProfile::Control,
                now,
            )),
            ..State::default()
        };
        let lineage = state.operation_store.lock().unwrap().lineage();
        Self {
            state,
            dispatcher: dispatch::Dispatcher::new(lineage),
        }
    }

    pub(super) fn tick(&mut self, now: u64) -> Vec<Frame> {
        let (tx, rx) = mpsc::sync_channel(64);
        dispatch::dispatch_once(&self.state, &tx, &mut self.dispatcher, now, now);
        rx.try_iter()
            .map(|out| match out {
                crate::Outbound::Seal(frame) => frame,
                crate::Outbound::Raw(_) => panic!("dispatcher emits sealed frames"),
            })
            .collect()
    }

    pub(super) fn api(&self, method: &str, params: &str, now: u64) -> routeloom_json::Json {
        let state = &self.state;
        let ctx = api1::ApiContext {
            principal: Some(routeloom_peercred::Principal::UnixUid(501)),
            acl: &state.acl,
            receive_log: &state.receive_log,
            operation_store: &state.operation_store,
            rate_limiter: &state.rate_limiter,
            session: &state.session,
            gateway_lane: &state.gateway_lane,
            node_table: &state.node_table,
            config_ops: &state.config_ops,
            group_ops: &state.group_ops,
            rollcall: &state.rollcall,
            telemetry_ops: &state.telemetry_ops,
            observation_ops: &state.observation_ops,
            remote_observation_ops: &state.remote_observation_ops,
            site: None,
            config_authority: None,
            config_profile: 0,
            link: api1::LinkStatus::default(),
            subscriptions: &state.subscriptions,
            conn_id: 1,
            event_ring: api1::EventRing {
                events: &state.events,
                next_seq: &state.event_seq,
                dropped: &state.events_dropped,
            },
            now_ms: now,
            now_mono: now,
        };
        let body =
            format!(r#"{{"v":1,"request_id":"mesh","method":"{method}","params":{params}}}"#);
        routeloom_json::parse(&api1::handle(body.as_bytes(), &ctx)).unwrap()
    }
}
