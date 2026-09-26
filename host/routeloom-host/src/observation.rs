//! observation_v1 USB lane (HostOps 0x70-0x72): read-only system health,
//! table occupancy, join milestones and selected-route detail for the
//! attached gateway, plus bounded change events. The API layer
//! (`health.get` / `topology.get`) submits and waits here; the lane thread
//! sends, expires and reaps; the USB read thread posts 0x71 replies and
//! folds 0x72 events into the cache. All three meet only here.
//!
//! Local-only by construction: the device answers for ITSELF. An observer
//! that is not the attached gateway is rejected at the API layer — remote
//! health arrives over the app layer (bench STATUS), never through this
//! lane, so no query here can be mistaken for mesh-wide truth.
//!
//! Clock domain: device ages map onto the host receive time
//! (`received_ms - age_ms`, an upper bound like node_status). A session
//! loss, a boot change or an event-sequence gap retires cached claims —
//! the API reports unknown until it re-pulls, never the last value.

use routeloom_protocol::host_ops::{ConfigOpsResult, CAP_HOST_OPS_V1};
use routeloom_protocol::observation::{
    decode_observation_event, decode_observation_page, encode_observation_query, observation_sub,
    ObservationPageHeader, ObservationQuery, CAP_OBSERVATION_V1, QUERY_EXACT, QUERY_SUBSCRIBE,
    RESULT_OK, SECTION_ROUTES, SUB_OBSERVATION_EVENT, SUB_OBSERVATION_PAGE,
};
use routeloom_protocol::{Frame, FrameKind};
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use crate::{mono_ms, Outbound, State};

/// Queries in flight at once; beyond this the API answers NO_CAPACITY
/// instead of queueing blindly.
pub const MAX_IN_FLIGHT: usize = 4;
/// Local USB round trip (no mesh leg); the API waiter holds a slightly
/// longer budget so the lane always resolves first.
pub const QUERY_TIMEOUT_MS: u64 = 1_500;
pub const API_WAIT_MS: u64 = 2_000;
/// A resolved-but-untaken outcome (its waiter already left) is reaped
/// after this long so abandoned queries cannot pin table slots.
const SETTLE_GRACE_MS: u64 = API_WAIT_MS;
const TICK_MS: u64 = 50;
/// Cache horizon for singleton sections (system/tables/milestones/summary):
/// `max_age_ms` beyond this still re-queries past it.
pub const MAX_AGE_LIMIT_MS: u64 = 60_000;

const REQUEST_BASE: u64 = 0x4F42_0000_0000_0000;
const REQUEST_MASK: u64 = 0xFFFF_0000_0000_0000;

/// True for the HostOps bodies this lane owns (0x71 replies; 0x70 is
/// host→device and never arrives from a well-behaved device).
pub fn owns_page(inner: &[u8]) -> bool {
    observation_sub(inner) == Some(SUB_OBSERVATION_PAGE)
}

/// True for unsolicited 0x72 change events.
pub fn owns_event(inner: &[u8]) -> bool {
    observation_sub(inner) == Some(SUB_OBSERVATION_EVENT)
}

/// True when an Error frame's request id is one this lane minted.
pub fn owns_request(request: u64) -> bool {
    request & REQUEST_MASK == REQUEST_BASE
}

/// The family rides the HostOps carrier: both bits must be advertised.
pub fn observation_capable(capability: u32) -> bool {
    capability & CAP_OBSERVATION_V1 != 0 && capability & CAP_HOST_OPS_V1 != 0
}

/// One validated API1 observation query.
#[derive(Clone, Copy, Debug)]
pub struct ObservationQueryParams {
    pub section: u8,
    pub after: u64,
    pub max_entries: u8,
    pub exact: bool,
    pub subscribe: bool,
}

/// Terminal state of one query: the 0x71 answer decoded, or the reason no
/// answer arrived.
#[derive(Debug)]
pub enum QueryOutcome {
    Page {
        header: ObservationPageHeader,
        body: Vec<u8>,
        received_ms: u64,
    },
    Device(ConfigOpsResult),
    DecodeError(String),
    Timeout,
    SessionLost,
    ErrorFrame(u16),
}

#[derive(Debug)]
struct PendingQuery {
    token: u64,
    session: u64,
    request: u64,
    params: ObservationQueryParams,
    submitted_ms: u64,
    sent: bool,
    outcome: Option<QueryOutcome>,
    settled_ms: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubmitError {
    NoCapacity,
}

/// Bounded table of in-flight observation queries plus the singleton
/// cache. The API layer submits, waits and reads the cache; the lane
/// thread sends, expires and reaps; the USB read thread posts replies
/// and folds 0x72 events into the cache. All three meet only here.
#[derive(Default)]
pub struct ObservationOps {
    ops: Mutex<HashMap<u64, PendingQuery>>,
    next: Mutex<u64>,
    change: Condvar,
    cache: Mutex<ObservationCache>,
}

impl ObservationOps {
    fn mint(&self) -> (u64, u64) {
        let mut next = self.next.lock().expect("observation ops poisoned");
        *next = next.wrapping_add(1);
        let token = if *next == 0 { 1 } else { *next };
        *next = token;
        (token, REQUEST_BASE | (token & !REQUEST_MASK))
    }

    pub fn submit(
        &self,
        params: ObservationQueryParams,
        session: u64,
        now_ms: u64,
    ) -> Result<u64, SubmitError> {
        let mut ops = self.ops.lock().expect("observation ops poisoned");
        if ops.len() >= MAX_IN_FLIGHT {
            return Err(SubmitError::NoCapacity);
        }
        let (token, request) = self.mint();
        ops.insert(
            token,
            PendingQuery {
                token,
                session,
                request,
                params,
                submitted_ms: now_ms,
                sent: false,
                outcome: None,
                settled_ms: None,
            },
        );
        drop(ops);
        self.change.notify_all();
        Ok(token)
    }

    pub fn wait_for(&self, token: u64, wait: Duration) -> Option<QueryOutcome> {
        let deadline = std::time::Instant::now() + wait;
        let mut ops = self.ops.lock().expect("observation ops poisoned");
        loop {
            let done = ops.get(&token).is_some_and(|op| op.outcome.is_some());
            if done {
                return ops.remove(&token).and_then(|op| op.outcome);
            }
            if !ops.contains_key(&token) {
                return None;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            ops = self
                .change
                .wait_timeout(ops, deadline - now)
                .expect("observation ops poisoned")
                .0;
        }
    }

    pub fn pending(&self) -> usize {
        self.ops.lock().expect("observation ops poisoned").len()
    }

    pub fn cached(
        &self,
        section: u8,
        session: u64,
        boot: u64,
        max_age_ms: u64,
        now_ms: u64,
    ) -> Option<CachedBody> {
        self.cache
            .lock()
            .expect("observation cache poisoned")
            .get(section, session, boot, max_age_ms, now_ms)
    }

    /// Current dirty generation; a page stores only against the mark its
    /// query took (see `store`).
    pub fn dirty_mark(&self) -> u64 {
        self.cache
            .lock()
            .expect("observation cache poisoned")
            .dirtied
    }

    /// Stores one decoded singleton page, unless a 0x72 event dirtied the
    /// cache after `store.dirty_mark` was taken (the page may predate the
    /// change — skip it and re-pull next time). The mark check and the put
    /// run under one lock, so an event either skips this store or dirties
    /// past it — a stale page can never clear a fresh dirty flag.
    pub fn store(&self, store: CacheStore) -> bool {
        let mut cache = self.cache.lock().expect("observation cache poisoned");
        if cache.dirtied != store.dirty_mark {
            return false;
        }
        cache.put(
            store.section,
            store.session,
            store.boot,
            store.body,
            store.revision,
            store.received_ms,
            store.armed,
        );
        true
    }

    #[cfg(test)]
    pub fn tokens(&self) -> Vec<u64> {
        self.ops
            .lock()
            .expect("observation ops poisoned")
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub fn request_for(&self, token: u64) -> Option<u64> {
        self.ops
            .lock()
            .expect("observation ops poisoned")
            .get(&token)
            .map(|op| op.request)
    }

    #[cfg(test)]
    pub fn submitted_ms_for(&self, token: u64) -> Option<u64> {
        self.ops
            .lock()
            .expect("observation ops poisoned")
            .get(&token)
            .map(|op| op.submitted_ms)
    }

    fn resolve(&self, request: u64, session: u64, outcome: QueryOutcome, now_ms: u64) -> bool {
        let mut ops = self.ops.lock().expect("observation ops poisoned");
        let Some(op) = ops
            .values_mut()
            .find(|op| op.request == request && op.session == session)
        else {
            return false;
        };
        if op.outcome.is_none() {
            op.outcome = Some(outcome);
            op.settled_ms = Some(now_ms);
        }
        drop(ops);
        self.change.notify_all();
        true
    }

    /// Posted by the USB read thread; never blocks it. Unknown requests
    /// are stale/foreign replies (a late answer past our timeout):
    /// ignored, never an event.
    pub fn post_reply(&self, request: u64, session: u64, body: Vec<u8>, now_ms: u64) -> bool {
        let outcome = match decode_observation_page(&body) {
            Ok((header, page_body)) if header.result == RESULT_OK => QueryOutcome::Page {
                header,
                body: page_body,
                received_ms: now_ms,
            },
            Ok((header, _)) => match ConfigOpsResult::try_from_u16(header.result) {
                Ok(result) => QueryOutcome::Device(result),
                Err(error) => QueryOutcome::DecodeError(error.to_string()),
            },
            Err(error) => QueryOutcome::DecodeError(error.to_string()),
        };
        // A page for another section than queried is a device bug made
        // visible (the request id matched, the content did not).
        if let QueryOutcome::Page { header, .. } = &outcome {
            let asked = {
                let ops = self.ops.lock().expect("observation ops poisoned");
                ops.values()
                    .find(|op| op.request == request && op.session == session)
                    .map(|op| op.params.section)
            };
            if let Some(asked) = asked {
                if header.section != asked {
                    return self.resolve(
                        request,
                        session,
                        QueryOutcome::DecodeError(format!(
                            "observation section mismatch: asked {asked} got {}",
                            header.section
                        )),
                        now_ms,
                    );
                }
            }
        }
        self.resolve(request, session, outcome, now_ms)
    }

    /// Posted by the USB read thread for an Error frame echoing our
    /// request id (a malformed 0x70 would land here — a daemon bug made
    /// visible, never a silent timeout).
    pub fn post_error(&self, request: u64, session: u64, code: u16) -> bool {
        self.resolve(request, session, QueryOutcome::ErrorFrame(code), mono_ms())
    }

    /// Called by the lane when it SENDS a query with the subscribe flag:
    /// the device re-arms there (its event sequence restarts at 1), so
    /// the next event re-syncs the watermark instead of looking like a
    /// replay of the previous arm. Cached bodies stay valid — the device
    /// re-baselines its digests at the same instant.
    pub fn note_resync_events(&self) {
        let mut cache = self.cache.lock().expect("observation cache poisoned");
        cache.event_seq = 0;
        cache.event_boot = None;
        cache.event_session = None;
    }
}

/// One lane step: resolve session losses and timeouts, issue unsent
/// queries, reap abandoned outcomes. Pure driver — the caller owns the
/// outbound queue and the clock.
pub fn observation_once(state: &State, outbound: &mpsc::SyncSender<Outbound>, now_ms: u64) {
    let live = {
        let info = state.session.lock().expect("session poisoned");
        if info.authenticated {
            info.id
        } else {
            None
        }
    };
    let mut send: Vec<(u64, Vec<u8>)> = Vec::new();
    {
        let ops = &state.observation_ops;
        let mut table = ops.ops.lock().expect("observation ops poisoned");
        let mut reap: Vec<u64> = Vec::new();
        for op in table.values_mut() {
            if let Some(settled) = op.settled_ms {
                if now_ms.saturating_sub(settled) >= SETTLE_GRACE_MS {
                    reap.push(op.token);
                }
                continue;
            }
            if live != Some(op.session) {
                op.outcome = Some(QueryOutcome::SessionLost);
                op.settled_ms = Some(now_ms);
                continue;
            }
            if now_ms.saturating_sub(op.submitted_ms) >= QUERY_TIMEOUT_MS {
                op.outcome = Some(QueryOutcome::Timeout);
                op.settled_ms = Some(now_ms);
                continue;
            }
            if op.sent {
                continue;
            }
            let query = ObservationQuery {
                section: op.params.section,
                max_entries: op.params.max_entries,
                flags: (if op.params.subscribe {
                    QUERY_SUBSCRIBE
                } else {
                    0
                }) | (if op.params.exact { QUERY_EXACT } else { 0 }),
                after: op.params.after,
            };
            match encode_observation_query(&query) {
                Ok(body) => {
                    if op.params.subscribe {
                        // The device re-arms (and restarts its event
                        // sequence) when it processes this query; the
                        // watermark must re-sync with the next event.
                        ops.note_resync_events();
                    }
                    send.push((op.request, body));
                }
                Err(error) => {
                    op.outcome = Some(QueryOutcome::DecodeError(error.to_string()));
                    op.settled_ms = Some(now_ms);
                }
            }
        }
        for token in reap {
            table.remove(&token);
        }
    }
    let mut progressed = false;
    for (request, body) in send {
        let frame = Frame {
            kind: FrameKind::HostOps,
            flags: 0,
            session: 0,
            request,
            body,
        };
        // The writer queue refused the frame: provably never sent, so the
        // query stays unsent for the next tick (its timeout still bounds
        // the wait — a clogged queue resolves Timeout, honestly).
        if outbound.try_send(Outbound::Seal(frame)).is_ok() {
            let mut table = state
                .observation_ops
                .ops
                .lock()
                .expect("observation ops poisoned");
            if let Some(op) = table.values_mut().find(|op| op.request == request) {
                op.sent = true;
            }
            progressed = true;
        }
    }
    if progressed {
        state.observation_ops.change.notify_all();
    }
}

/// The observation thread: runs for the daemon's lifetime; idle (no
/// frames) while no query is submitted.
pub fn observation_loop(state: Arc<State>, outbound: mpsc::SyncSender<Outbound>) {
    loop {
        observation_once(&state, &outbound, mono_ms());
        let ops = state
            .observation_ops
            .ops
            .lock()
            .expect("observation ops poisoned");
        let _ = state
            .observation_ops
            .change
            .wait_timeout(ops, Duration::from_millis(TICK_MS));
    }
}

/// Last good singleton bodies, pinned to the (session, boot) that served
/// them. Routes pages are always freshly queried (one USB query per API
/// page — bounded like diagnostics.snapshot); only the singletons cache.
#[derive(Debug, Default)]
pub struct ObservationCache {
    session: Option<u64>,
    boot: Option<u64>,
    system: Option<CachedBody>,
    tables: Option<CachedBody>,
    milestones: Option<CachedBody>,
    summary: Option<CachedBody>,
    /// Last 0x72 sequence per subscription epoch (boot, session).
    event_seq: u32,
    event_boot: Option<u64>,
    event_session: Option<u64>,
    /// Set by 0x72; a set flag forces the next read of its sections to
    /// re-query instead of serving the cache.
    dirty_topology: bool,
    dirty_milestones: bool,
    /// Bumped every time a dirty flag is set. A page stores only when the
    /// mark its query took still matches — an event that landed between
    /// the device taking the page and the host storing it skips the store
    /// (one extra query later, never a stale cache).
    dirtied: u64,
}

/// One cached singleton: raw section body plus the host receive time the
/// ages inside it are mapped against.
#[derive(Clone, Debug)]
pub struct CachedBody {
    pub body: Vec<u8>,
    pub revision: u32,
    pub received_ms: u64,
    pub armed: bool,
}

/// One decoded singleton page offered to the cache, with the dirty mark
/// its query took before submitting.
pub struct CacheStore {
    pub section: u8,
    pub session: u64,
    pub boot: u64,
    pub body: Vec<u8>,
    pub revision: u32,
    pub received_ms: u64,
    pub armed: bool,
    pub dirty_mark: u64,
}

impl ObservationCache {
    fn pinned(&self, session: u64, boot: u64) -> bool {
        self.session == Some(session) && self.boot == Some(boot)
    }

    /// Records the serving session/boot; returns false when the page came
    /// from a different boot than the cache holds (the caller retires
    /// everything first).
    pub fn note_page(&mut self, session: u64, boot: u64) {
        if self.session != Some(session) || self.boot != Some(boot) {
            *self = ObservationCache {
                session: Some(session),
                boot: Some(boot),
                ..ObservationCache::default()
            };
        }
    }

    pub fn get(
        &self,
        section: u8,
        session: u64,
        boot: u64,
        max_age_ms: u64,
        now_ms: u64,
    ) -> Option<CachedBody> {
        if !self.pinned(session, boot) {
            return None;
        }
        if section == routeloom_protocol::observation::SECTION_SUMMARY && self.dirty_topology {
            return None;
        }
        if section == routeloom_protocol::observation::SECTION_MILESTONES && self.dirty_milestones {
            return None;
        }
        let cached = match section {
            s if s == routeloom_protocol::observation::SECTION_SYSTEM => self.system.as_ref()?,
            s if s == routeloom_protocol::observation::SECTION_TABLES => self.tables.as_ref()?,
            s if s == routeloom_protocol::observation::SECTION_MILESTONES => {
                self.milestones.as_ref()?
            }
            s if s == routeloom_protocol::observation::SECTION_SUMMARY => self.summary.as_ref()?,
            _ => return None,
        };
        if max_age_ms == 0 {
            return None;
        }
        if now_ms.saturating_sub(cached.received_ms) > max_age_ms {
            return None;
        }
        Some(cached.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn set_dirty(&mut self, topology: bool, milestones: bool) {
        self.dirty_topology |= topology;
        self.dirty_milestones |= milestones;
        self.dirtied = self.dirtied.wrapping_add(1);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put(
        &mut self,
        section: u8,
        session: u64,
        boot: u64,
        body: Vec<u8>,
        revision: u32,
        received_ms: u64,
        armed: bool,
    ) {
        self.note_page(session, boot);
        let cached = Some(CachedBody {
            body,
            revision,
            received_ms,
            armed,
        });
        // A fresh read clears the change flag for its sections: the cache
        // is current again as of this receive time.
        if section == routeloom_protocol::observation::SECTION_MILESTONES {
            self.dirty_milestones = false;
            self.milestones = cached;
        } else if section == routeloom_protocol::observation::SECTION_SUMMARY {
            self.dirty_topology = false;
            self.summary = cached;
        } else if section == routeloom_protocol::observation::SECTION_SYSTEM {
            self.system = cached;
        } else if section == routeloom_protocol::observation::SECTION_TABLES {
            self.tables = cached;
        }
    }
}

/// What a 0x72 event means for the API event stream, decided while
/// holding the cache lock (the read thread only pushes strings).
#[derive(Debug)]
pub enum ObservationNotice {
    TopologyChanged {
        mask: u8,
        route_digest: u32,
        neighbor_digest: u32,
    },
    MilestoneAdvanced {
        generation: u32,
    },
    Gap {
        expected: u32,
        received: u32,
        lost: u32,
    },
}

impl ObservationOps {
    /// Folds one 0x72 body into the cache; returns the notices to emit
    /// (at most a gap plus the event itself). Never blocks the read
    /// thread on anything but the cache mutex. Events from a foreign
    /// (session, boot) are ignored — a previous subscription epoch's
    /// stragglers.
    pub fn on_event(&self, session: u64, body: &[u8]) -> Vec<ObservationNotice> {
        let event = match decode_observation_event(body) {
            Ok(event) => event,
            Err(_) => return Vec::new(),
        };
        self.on_decoded_event(session, &event)
    }

    fn on_decoded_event(
        &self,
        session: u64,
        event: &routeloom_protocol::observation::ObservationEvent,
    ) -> Vec<ObservationNotice> {
        let mut cache = self.cache.lock().expect("observation cache poisoned");
        // First event of an epoch syncs the sequence without alleging a gap;
        // an older boot/session is a straggler from a dead subscription.
        if cache.event_session != Some(session) || cache.event_boot != Some(event.boot_id) {
            cache.event_session = Some(session);
            cache.event_boot = Some(event.boot_id);
            cache.event_seq = event.sequence;
        } else if event.sequence <= cache.event_seq {
            return Vec::new();
        } else {
            let mut notices = Vec::new();
            if event.sequence != cache.event_seq + 1 {
                notices.push(ObservationNotice::Gap {
                    expected: cache.event_seq + 1,
                    received: event.sequence,
                    lost: event.sequence - cache.event_seq - 1,
                });
                // A gap retires the topology/milestone caches: the host
                // cannot know what it missed, so it must re-pull.
                cache.set_dirty(true, true);
            }
            cache.event_seq = event.sequence;
            if event.kind == routeloom_protocol::observation::EVENT_TOPOLOGY {
                cache.set_dirty(true, false);
                notices.push(ObservationNotice::TopologyChanged {
                    mask: event.mask,
                    route_digest: event.revision,
                    neighbor_digest: event.extra,
                });
            } else {
                cache.set_dirty(false, true);
                notices.push(ObservationNotice::MilestoneAdvanced {
                    generation: event.revision,
                });
            }
            return notices;
        }
        // Fresh epoch: still apply the event itself (it may be the only
        // notice of a change that happened before we subscribed).
        if event.kind == routeloom_protocol::observation::EVENT_TOPOLOGY {
            cache.set_dirty(true, false);
            vec![ObservationNotice::TopologyChanged {
                mask: event.mask,
                route_digest: event.revision,
                neighbor_digest: event.extra,
            }]
        } else {
            cache.set_dirty(false, true);
            vec![ObservationNotice::MilestoneAdvanced {
                generation: event.revision,
            }]
        }
    }
}

/// Maps a device-monotonic age onto the host receive time (upper bound,
/// USB latency included); None when the age is the unknown sentinel.
#[must_use]
pub fn age_to_host_ms(received_ms: u64, age_ms: u32) -> Option<u64> {
    if age_ms == routeloom_protocol::observation::AGE_UNKNOWN {
        None
    } else {
        Some(received_ms.saturating_sub(u64::from(age_ms)))
    }
}

/// True for the routes section (the only paginated one).
#[must_use]
pub fn is_routes_section(section: u8) -> bool {
    section == SECTION_ROUTES
}

/// Renders one decoded section body as JSON. Unknown sentinels become
/// null — never a fabricated zero — and device ages map onto the host
/// receive time (upper bound, USB latency included).
pub fn system_json(
    system: &routeloom_protocol::observation::ObservationSystem,
    received_ms: u64,
) -> String {
    use routeloom_protocol::observation::{
        coord_mode_name, power_name, profile_name, reset_name, HEAP_UNKNOWN,
    };
    let heap = |bytes: u32| {
        if bytes == HEAP_UNKNOWN {
            "null".to_string()
        } else {
            bytes.to_string()
        }
    };
    format!(
        "{{\"uptime_ms\":{},\"booted_at_ms\":{},\"heap\":{{\"free_bytes\":{},\"min_bytes\":{},\"largest_bytes\":{}}},\"reset\":{{\"code\":{},\"name\":\"{}\"}},\"power\":{{\"code\":{},\"name\":\"{}\"}},\"coord\":{{\"code\":{},\"name\":\"{}\"}},\"profile\":{{\"code\":{},\"name\":\"{}\"}}}}",
        system.uptime_ms,
        received_ms.saturating_sub(system.uptime_ms),
        heap(system.heap_free_bytes),
        heap(system.heap_min_bytes),
        heap(system.heap_largest_bytes),
        system.reset_code,
        reset_name(system.reset_code),
        system.power_mode,
        power_name(system.power_mode),
        system.coord_mode,
        coord_mode_name(system.coord_mode),
        system.sec_profile,
        profile_name(system.sec_profile),
    )
}

pub fn tables_json(tables: &routeloom_protocol::observation::ObservationTables) -> String {
    format!(
        "{{\"neighbor\":{{\"active\":{},\"total\":{}}},\"route\":{{\"reachable\":{},\"total\":{}}},\"link_sessions\":{{\"active\":{},\"capacity\":{}}},\"end_sessions\":{{\"active\":{},\"capacity\":{}}},\"dedup\":{{\"resident\":{},\"terminal\":{},\"capacity\":{},\"refused\":{},\"evicted\":{}}},\"tx\":{{\"used\":{},\"capacity\":{}}},\"group\":{{\"trees\":{},\"origins\":{}}}}}",
        tables.neighbor_active,
        tables.neighbor_total,
        tables.route_reachable,
        tables.route_total,
        tables.link_sessions,
        tables.link_cap,
        tables.end_sessions,
        tables.end_cap,
        tables.dedup_resident,
        tables.dedup_terminal,
        tables.dedup_cap,
        tables.dedup_refused,
        tables.dedup_evicted,
        tables.tx_used,
        tables.tx_cap,
        tables.group_trees,
        tables.group_origins,
    )
}

pub fn milestones_json(
    milestones: &routeloom_protocol::observation::ObservationMilestones,
    received_ms: u64,
) -> String {
    use routeloom_protocol::observation::{coord_mode_name, joiner_name, membership_name};
    let at = |age_ms: u32| {
        age_to_host_ms(received_ms, age_ms).map_or("null".to_string(), |ms| ms.to_string())
    };
    format!(
        "{{\"mode\":{{\"code\":{},\"name\":\"{}\"}},\"membership\":{{\"code\":{},\"name\":\"{}\"}},\"joiner\":{{\"code\":{},\"name\":\"{}\"}},\"adopted\":{},\"confirmed\":{},\"attempts\":{},\"adopted_node\":{},\"join_started_at_ms\":{},\"adopted_at_ms\":{},\"confirmed_at_ms\":{}}}",
        milestones.mode,
        coord_mode_name(milestones.mode),
        milestones.membership,
        membership_name(milestones.membership),
        milestones.joiner_state,
        joiner_name(milestones.joiner_state),
        milestones.adopted(),
        milestones.confirmed(),
        milestones.attempts,
        if milestones.adopted() {
            format!("\"{:016x}\"", milestones.adopted_node)
        } else {
            "null".to_string()
        },
        at(milestones.join_started_age_ms),
        at(milestones.adopted_age_ms),
        at(milestones.confirmed_age_ms),
    )
}

pub fn summary_json(summary: &routeloom_protocol::observation::ObservationSummary) -> String {
    format!(
        "{{\"neighbor_digest\":{},\"route_digest\":{},\"neighbor\":{{\"active\":{},\"total\":{}}},\"route\":{{\"reachable\":{},\"total\":{}}},\"milestone_gen\":{}}}",
        summary.neighbor_digest,
        summary.route_digest,
        summary.neighbor_active,
        summary.neighbor_total,
        summary.route_reachable,
        summary.route_total,
        summary.milestone_gen,
    )
}

/// Renders one route entry. A lost (invalid) entry keeps its retraction
/// identity (generation/sequence) but its next hop, metric and remaining
/// lifetime are meaningless — null, never zero-filled guesses.
pub fn route_entry_json(entry: &routeloom_protocol::observation::RouteDetailEntry) -> String {
    format!(
        "{{\"destination\":\"{:016x}\",\"next_hop\":{},\"generation\":{},\"sequence\":{},\"metric\":{},\"valid\":{},\"remaining_ms\":{}}}",
        entry.destination,
        if entry.valid {
            format!("\"{:016x}\"", entry.next_hop)
        } else {
            "null".to_string()
        },
        entry.generation,
        entry.sequence,
        if entry.valid {
            entry.metric.to_string()
        } else {
            "null".to_string()
        },
        entry.valid,
        if entry.valid {
            entry.remaining_ms.to_string()
        } else {
            "null".to_string()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ranges_do_not_overlap() {
        assert!(owns_request(REQUEST_BASE | 7));
        assert!(!owns_request(0x544C_0000_0000_0007));
        assert!(!owns_request(0));
    }

    #[test]
    fn cache_pins_session_and_boot() {
        let mut cache = ObservationCache::default();
        cache.put(0, 11, 22, vec![1, 2], 0, 1000, false);
        assert!(cache.get(0, 11, 22, 60_000, 2000).is_some());
        assert!(cache.get(0, 11, 22, 60_000, 1000 + 60_001).is_none());
        assert!(cache.get(0, 11, 22, 0, 1000).is_none());
        assert!(cache.get(0, 12, 22, 60_000, 1000).is_none());
        assert!(cache.get(0, 11, 23, 60_000, 1000).is_none());
        // A new boot retires everything, even pinned reads.
        cache.note_page(11, 23);
        assert!(cache.get(0, 11, 23, 60_000, 1000).is_none());
    }

    #[test]
    fn events_drive_dirty_and_gaps() {
        use routeloom_protocol::observation::*;
        let ops = ObservationOps::default();
        let mk = |seq: u32, kind: u8| {
            encode_observation_event(&ObservationEvent {
                sequence: seq,
                kind,
                mask: if kind == EVENT_TOPOLOGY {
                    EVENT_MASK_ROUTES
                } else {
                    0
                },
                boot_id: 9,
                revision: 100 + seq,
                extra: 200,
            })
            .unwrap()
        };
        // The arming query's page is stored before any event of the arm
        // can arrive (the reply precedes later events on the wire), which
        // pins the cache epoch; a first store past events would resync it.
        let mark = ops.dirty_mark();
        assert!(ops.store(CacheStore {
            section: 3,
            session: 7,
            boot: 9,
            body: vec![0; 24],
            revision: 1,
            received_ms: 1000,
            armed: true,
            dirty_mark: mark,
        }));
        // First event of the epoch: applied, no gap alleged.
        let first = ops.on_event(7, &mk(5, EVENT_TOPOLOGY));
        assert_eq!(first.len(), 1);
        assert!(matches!(
            first[0],
            ObservationNotice::TopologyChanged { .. }
        ));
        // Contiguous: no gap.
        let next = ops.on_event(7, &mk(6, EVENT_MILESTONE));
        assert_eq!(next.len(), 1);
        assert!(matches!(
            next[0],
            ObservationNotice::MilestoneAdvanced { generation: 106 }
        ));
        // Skip: gap plus the event, caches dirtied. The store lands in the
        // same epoch, so the watermark survives it.
        let mark = ops.dirty_mark();
        assert!(ops.store(CacheStore {
            section: 2,
            session: 7,
            boot: 9,
            body: vec![0; 32],
            revision: 1,
            received_ms: 1000,
            armed: true,
            dirty_mark: mark,
        }));
        assert!(ops.cached(2, 7, 9, 60_000, 1000).is_some());
        let gap = ops.on_event(7, &mk(9, EVENT_TOPOLOGY));
        assert_eq!(gap.len(), 2);
        assert!(matches!(
            gap[0],
            ObservationNotice::Gap {
                expected: 7,
                received: 9,
                lost: 2
            }
        ));
        assert!(ops.cached(2, 7, 9, 60_000, 1000).is_none());
        // Replays are silent; a new session epoch re-syncs.
        assert!(ops.on_event(7, &mk(9, EVENT_TOPOLOGY)).is_empty());
        assert_eq!(ops.on_event(8, &mk(10, EVENT_TOPOLOGY)).len(), 1);
    }

    #[test]
    fn age_mapping() {
        assert_eq!(age_to_host_ms(10_000, 250), Some(9750));
        assert_eq!(age_to_host_ms(100, 250), Some(0));
        assert_eq!(age_to_host_ms(10_000, u32::MAX), None);
    }

    #[test]
    fn renders_unknown_as_null() {
        use routeloom_protocol::observation::*;
        let system = ObservationSystem {
            uptime_ms: 1000,
            heap_free_bytes: HEAP_UNKNOWN,
            heap_min_bytes: 2,
            heap_largest_bytes: HEAP_UNKNOWN,
            reset_code: 3,
            power_mode: 9,
            ..ObservationSystem::default()
        };
        let rendered = system_json(&system, 10_000);
        assert!(rendered.contains("\"booted_at_ms\":9000"), "{rendered}");
        assert!(rendered.contains("\"free_bytes\":null"), "{rendered}");
        assert!(rendered.contains("\"min_bytes\":2"), "{rendered}");
        assert!(
            rendered.contains("\"reset\":{\"code\":3,\"name\":\"watchdog\"}"),
            "{rendered}"
        );
        assert!(
            rendered.contains("\"power\":{\"code\":9,\"name\":\"unknown\"}"),
            "{rendered}"
        );

        let milestones = ObservationMilestones {
            mode: 3,
            membership: 5,
            joiner_state: 2,
            attempts: 1,
            join_started_age_ms: AGE_UNKNOWN,
            adopted_age_ms: 50,
            confirmed_age_ms: AGE_UNKNOWN,
            adopted_node: 0x0A,
            ..ObservationMilestones::default()
        };
        let rendered = milestones_json(&milestones, 10_000);
        assert!(rendered.contains("\"adopted\":false"), "{rendered}");
        assert!(rendered.contains("\"adopted_node\":null"), "{rendered}");
        assert!(
            rendered.contains("\"join_started_at_ms\":null"),
            "{rendered}"
        );
        assert!(rendered.contains("\"adopted_at_ms\":9950"), "{rendered}");

        let lost = RouteDetailEntry {
            destination: 7,
            generation: 4,
            sequence: 9,
            ..RouteDetailEntry::default()
        };
        let rendered = route_entry_json(&lost);
        assert!(rendered.contains("\"valid\":false"), "{rendered}");
        assert!(rendered.contains("\"next_hop\":null"), "{rendered}");
        assert!(rendered.contains("\"generation\":4"), "{rendered}");
        assert!(rendered.contains("\"remaining_ms\":null"), "{rendered}");
    }

    #[test]
    fn stale_mark_skips_the_store() {
        use routeloom_protocol::observation::*;
        let ops = ObservationOps::default();
        let mark = ops.dirty_mark();
        // An event between the mark and the store means the page may
        // predate the change: the store is skipped, the dirty flag stands.
        let event = encode_observation_event(&ObservationEvent {
            sequence: 1,
            kind: EVENT_TOPOLOGY,
            mask: EVENT_MASK_ROUTES,
            boot_id: 9,
            revision: 100,
            extra: 200,
        })
        .unwrap();
        ops.on_event(7, &event);
        assert!(!ops.store(CacheStore {
            section: 3,
            session: 7,
            boot: 9,
            body: vec![0; 24],
            revision: 1,
            received_ms: 1000,
            armed: true,
            dirty_mark: mark,
        }));
        assert!(ops.cached(3, 7, 9, 60_000, 1000).is_none());
        // A page taken past the event (fresh mark) stores and clears.
        let mark = ops.dirty_mark();
        assert!(ops.store(CacheStore {
            section: 3,
            session: 7,
            boot: 9,
            body: vec![0; 24],
            revision: 1,
            received_ms: 1000,
            armed: true,
            dirty_mark: mark,
        }));
        assert!(ops.cached(3, 7, 9, 60_000, 1000).is_some());
    }

    #[test]
    fn resync_reopens_the_event_epoch() {
        use routeloom_protocol::observation::*;
        let ops = ObservationOps::default();
        let mk = |seq: u32| {
            encode_observation_event(&ObservationEvent {
                sequence: seq,
                kind: EVENT_TOPOLOGY,
                mask: EVENT_MASK_ROUTES,
                boot_id: 9,
                revision: 100,
                extra: 200,
            })
            .unwrap()
        };
        assert_eq!(ops.on_event(7, &mk(5)).len(), 1);
        // A re-arm restarts the device sequence at 1; without a resync
        // those events would die as replays.
        ops.note_resync_events();
        let notices = ops.on_event(7, &mk(1));
        assert_eq!(notices.len(), 1);
        assert!(matches!(
            notices[0],
            ObservationNotice::TopologyChanged { .. }
        ));
    }
}
