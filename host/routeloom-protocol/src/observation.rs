//! observation_v1 HostOps codec (subcommands 0x70-0x72): read-only system
//! health, table occupancy, join milestones, topology summary and paginated
//! selected-route detail for the USB-attached node, plus bounded change
//! events. Byte-identical to the device side in
//! `components/routeloom/{include/routeloom/{observation,usb_host_ops}.hpp,
//! src/{observation,usb_host_ops}.cpp}`.
//!
//! Inner common form: schema:u8=1, sub:u8, payload_len:u16, payload —
//! big-endian, exact length only.
//!
//! Clock domain: the device never sends absolute timestamps here. Ages and
//! uptime are durations on the device monotonic clock; the host maps an age
//! onto its own receive time (`received_ms - age_ms`, an upper bound like
//! node_status `heard_age_ms`). A new `boot_id` retires every cached claim.

use crate::host_ops::{HostOpsError, HOST_OPS_SCHEMA};

/// HelloAck capability bit: the device serves 0x70-0x72.
pub const CAP_OBSERVATION_V1: u32 = 1 << 11;

pub const SUB_OBSERVATION_QUERY: u8 = 0x70;
pub const SUB_OBSERVATION_PAGE: u8 = 0x71;
pub const SUB_OBSERVATION_EVENT: u8 = 0x72;

/// Section ids (ObservationSection).
pub const SECTION_SYSTEM: u8 = 0;
pub const SECTION_TABLES: u8 = 1;
pub const SECTION_MILESTONES: u8 = 2;
pub const SECTION_SUMMARY: u8 = 3;
pub const SECTION_ROUTES: u8 = 4;
pub const SECTION_NEIGHBORS: u8 = 5;

pub const QUERY_SUBSCRIBE: u8 = 0x01;
pub const QUERY_EXACT: u8 = 0x02;
pub const PAGE_MORE: u8 = 0x01;
pub const PAGE_ARMED: u8 = 0x02;

pub const EVENT_TOPOLOGY: u8 = 1;
pub const EVENT_MILESTONE: u8 = 2;
pub const EVENT_MASK_NEIGHBORS: u8 = 1 << 0;
pub const EVENT_MASK_ROUTES: u8 = 1 << 1;

pub const INNER_HEAD_SIZE: usize = 4;
pub const QUERY_PAYLOAD: usize = 12;
pub const PAGE_FIXED: usize = 26;
pub const SYSTEM_BODY: usize = 28;
pub const TABLES_BODY: usize = 36;
pub const MILESTONES_BODY: usize = 44;
pub const MILESTONE_AGE_UNKNOWN: u64 = u64::MAX;
pub const SUMMARY_BODY: usize = 24;
pub const ROUTE_ENTRY_SIZE: usize = 30;
pub const NEIGHBOR_ENTRY_SIZE: usize = 24;
/// Device page buffer bound (kObservationRoutesPageMax).
pub const PAGE_MAX: usize = 8;
pub const PAGE_MAX_PAYLOAD: usize = PAGE_FIXED + PAGE_MAX * ROUTE_ENTRY_SIZE;
pub const EVENT_PAYLOAD: usize = 24;

/// Age/heap sentinel: not reached / not readable.
pub const AGE_UNKNOWN: u32 = u32::MAX;
pub const HEAP_UNKNOWN: u32 = u32::MAX;

/// ConfigOpsResult values this surface answers with.
pub const RESULT_OK: u16 = 0;
pub const RESULT_UNSUPPORTED: u16 = 4;
pub const RESULT_INDETERMINATE: u16 = 7;

fn config_result_valid(result: u16) -> bool {
    matches!(result, 0 | 1 | 3 | 4 | 5 | 7 | 8 | 9)
}

/// Reset-cause registry (ObservationReset).
pub const RESET_UNKNOWN: u8 = 0;
/// Power-mode registry (ObservationPower).
pub const POWER_UNKNOWN: u8 = 0;
/// Coordinator-mode registry (ObservationCoordMode).
pub const COORD_UNKNOWN: u8 = 0;
/// Security-profile registry (ObservationProfile).
pub const PROFILE_UNKNOWN: u8 = 0;
/// Membership registry (ObservationMembership).
pub const MEMBERSHIP_UNKNOWN: u8 = 0;
/// Joiner-state registry (ObservationJoiner).
pub const JOINER_UNKNOWN: u8 = 0;
/// Neighbor-phase registry (ObservationNeighborPhase): 0 is unknown, 1..=10
/// the discovery NeighborPhase shifted by one.
pub const PHASE_UNKNOWN: u8 = 0;

/// Neighbor entry flags.
pub const NBR_ACTIVE: u8 = 1 << 0;
pub const NBR_RSSI_VALID: u8 = 1 << 1;
pub const NBR_HEARD_VALID: u8 = 1 << 2;

pub const MILESTONE_ADOPTED: u8 = 1 << 0;
pub const MILESTONE_CONFIRMED: u8 = 1 << 1;

/// Human names for the registries (JSON `*_name` fields). Unknown codes
/// render as `"unknown"` — the daemon never invents a meaning for a code
/// it was not built with.
#[must_use]
pub const fn reset_name(code: u8) -> &'static str {
    match code {
        1 => "power_on",
        2 => "software",
        3 => "watchdog",
        4 => "deep_sleep_wake",
        5 => "panic",
        6 => "brownout",
        7 => "other",
        _ => "unknown",
    }
}

#[must_use]
pub const fn power_name(code: u8) -> &'static str {
    match code {
        1 => "running",
        2 => "draining",
        3 => "sleeping",
        _ => "unknown",
    }
}

#[must_use]
pub const fn coord_mode_name(code: u8) -> &'static str {
    match code {
        1 => "fresh",
        2 => "zero_touch",
        3 => "member",
        4 => "dev",
        5 => "removed",
        6 => "recovery",
        _ => "unknown",
    }
}

#[must_use]
pub const fn profile_name(code: u8) -> &'static str {
    match code {
        1 => "member_edhoc",
        2 => "dev_ram",
        // 3 named the removed dev-PSK fixture profile; reserved.
        _ => "unknown",
    }
}

#[must_use]
pub const fn membership_name(code: u8) -> &'static str {
    match code {
        1 => "unprovisioned",
        2 => "discovering",
        3 => "authenticating",
        4 => "authorized_pending_commit",
        5 => "member",
        6 => "revoked",
        _ => "unknown",
    }
}

#[must_use]
pub const fn joiner_name(code: u8) -> &'static str {
    match code {
        1 => "stopped",
        2 => "active",
        3 => "ready",
        4 => "removed",
        5 => "recovery_required",
        _ => "unknown",
    }
}

#[must_use]
pub const fn neighbor_phase_name(code: u8) -> &'static str {
    match code {
        1 => "candidate",
        2 => "authenticating",
        3 => "authenticated",
        4 => "approval_pending",
        5 => "bound",
        6 => "reachable",
        7 => "suspended",
        8 => "stale",
        9 => "conflict",
        10 => "revoked",
        _ => "unknown",
    }
}

/// The sub byte of an observation inner body (0x70-0x72), if it is one.
#[must_use]
pub fn observation_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    matches!(
        inner[1],
        SUB_OBSERVATION_QUERY | SUB_OBSERVATION_PAGE | SUB_OBSERVATION_EVENT
    )
    .then_some(inner[1])
}

fn head(out: &mut Vec<u8>, sub: u8, payload_len: usize) {
    out.push(HOST_OPS_SCHEMA);
    out.push(sub);
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());
}

fn body(inner: &[u8], sub: u8, min: usize, max: usize) -> Result<&[u8], HostOpsError> {
    if inner.len() < INNER_HEAD_SIZE || inner.len() > INNER_HEAD_SIZE + max {
        return Err(HostOpsError::LengthMismatch);
    }
    if inner[0] != HOST_OPS_SCHEMA {
        return Err(HostOpsError::BadSchema);
    }
    if inner[1] != sub {
        return Err(HostOpsError::SubcommandMismatch);
    }
    let payload_len = usize::from(u16::from_be_bytes([inner[2], inner[3]]));
    if payload_len != inner.len() - INNER_HEAD_SIZE || payload_len < min || payload_len > max {
        return Err(HostOpsError::LengthMismatch);
    }
    Ok(&inner[INNER_HEAD_SIZE..])
}

fn be<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], HostOpsError> {
    bytes
        .get(offset..offset + N)
        .ok_or(HostOpsError::Truncated)?
        .try_into()
        .map_err(|_| HostOpsError::Truncated)
}

fn section_valid(section: u8) -> bool {
    section <= SECTION_NEIGHBORS
}

/// 0x70 OBSERVATION_QUERY (H→G).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationQuery {
    pub section: u8,
    /// 1..=PAGE_MAX (singletons always answer count 1).
    pub max_entries: u8,
    /// QUERY_SUBSCRIBE (re)arms the 0x72 stream; QUERY_EXACT (routes only)
    /// makes `after` one destination instead of a cursor.
    pub flags: u8,
    /// Exclusive NodeId cursor, or the exact destination with EXACT.
    pub after: u64,
}

fn check_query(query: &ObservationQuery) -> Result<(), HostOpsError> {
    if !section_valid(query.section) {
        return Err(HostOpsError::Invalid("observation section"));
    }
    if query.after == u64::MAX {
        return Err(HostOpsError::Invalid("observation after"));
    }
    if query.max_entries == 0 || usize::from(query.max_entries) > PAGE_MAX {
        return Err(HostOpsError::Invalid("observation max_entries"));
    }
    if query.flags & !(QUERY_SUBSCRIBE | QUERY_EXACT) != 0 {
        return Err(HostOpsError::Invalid("observation query flags"));
    }
    if query.flags & QUERY_EXACT != 0
        && ((query.section != SECTION_ROUTES && query.section != SECTION_NEIGHBORS)
            || query.after == 0)
    {
        return Err(HostOpsError::Invalid("observation exact"));
    }
    Ok(())
}

pub fn encode_observation_query(query: &ObservationQuery) -> Result<Vec<u8>, HostOpsError> {
    check_query(query)?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + QUERY_PAYLOAD);
    head(&mut out, SUB_OBSERVATION_QUERY, QUERY_PAYLOAD);
    out.push(query.section);
    out.push(query.flags);
    out.push(query.max_entries);
    out.push(0);
    out.extend_from_slice(&query.after.to_be_bytes());
    Ok(out)
}

pub fn decode_observation_query(inner: &[u8]) -> Result<ObservationQuery, HostOpsError> {
    let payload = body(inner, SUB_OBSERVATION_QUERY, QUERY_PAYLOAD, QUERY_PAYLOAD)?;
    if payload[3] != 0 {
        return Err(HostOpsError::Invalid("observation query reserved"));
    }
    let query = ObservationQuery {
        section: payload[0],
        flags: payload[1],
        max_entries: payload[2],
        after: u64::from_be_bytes(be(payload, 4)?),
    };
    check_query(&query)?;
    Ok(query)
}

/// System health singleton (28-byte body).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationSystem {
    pub uptime_ms: u64,
    pub heap_free_bytes: u32,
    pub heap_min_bytes: u32,
    pub heap_largest_bytes: u32,
    pub reset_code: u8,
    pub power_mode: u8,
    pub coord_mode: u8,
    pub sec_profile: u8,
}

pub fn encode_observation_system(body: &ObservationSystem) -> Vec<u8> {
    let mut out = Vec::with_capacity(SYSTEM_BODY);
    out.extend_from_slice(&body.uptime_ms.to_be_bytes());
    out.extend_from_slice(&body.heap_free_bytes.to_be_bytes());
    out.extend_from_slice(&body.heap_min_bytes.to_be_bytes());
    out.extend_from_slice(&body.heap_largest_bytes.to_be_bytes());
    out.push(body.reset_code);
    out.push(body.power_mode);
    out.push(body.coord_mode);
    out.push(body.sec_profile);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

pub fn decode_observation_system(body: &[u8]) -> Result<ObservationSystem, HostOpsError> {
    if body.len() != SYSTEM_BODY {
        return Err(HostOpsError::LengthMismatch);
    }
    let out = ObservationSystem {
        uptime_ms: u64::from_be_bytes(be(body, 0)?),
        heap_free_bytes: u32::from_be_bytes(be(body, 8)?),
        heap_min_bytes: u32::from_be_bytes(be(body, 12)?),
        heap_largest_bytes: u32::from_be_bytes(be(body, 16)?),
        reset_code: body[20],
        power_mode: body[21],
        coord_mode: body[22],
        sec_profile: body[23],
    };
    if u32::from_be_bytes(be(body, 24)?) != 0 {
        return Err(HostOpsError::Invalid("observation system reserved"));
    }
    Ok(out)
}

/// Table occupancy singleton (36-byte body).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationTables {
    pub neighbor_active: u16,
    pub neighbor_total: u16,
    pub route_reachable: u16,
    pub route_total: u16,
    pub link_sessions: u16,
    pub link_cap: u16,
    pub end_sessions: u16,
    pub end_cap: u16,
    pub dedup_resident: u16,
    pub dedup_terminal: u16,
    pub dedup_cap: u16,
    pub tx_used: u8,
    pub tx_cap: u8,
    pub group_trees: u8,
    pub group_origins: u8,
    pub dedup_refused: u32,
    pub dedup_evicted: u32,
}

pub fn encode_observation_tables(body: &ObservationTables) -> Vec<u8> {
    let mut out = Vec::with_capacity(TABLES_BODY);
    for v in [
        body.neighbor_active,
        body.neighbor_total,
        body.route_reachable,
        body.route_total,
        body.link_sessions,
        body.link_cap,
        body.end_sessions,
        body.end_cap,
        body.dedup_resident,
        body.dedup_terminal,
        body.dedup_cap,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.push(body.tx_used);
    out.push(body.tx_cap);
    out.push(body.group_trees);
    out.push(body.group_origins);
    out.extend_from_slice(&body.dedup_refused.to_be_bytes());
    out.extend_from_slice(&body.dedup_evicted.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

pub fn decode_observation_tables(body: &[u8]) -> Result<ObservationTables, HostOpsError> {
    if body.len() != TABLES_BODY {
        return Err(HostOpsError::LengthMismatch);
    }
    let u16at =
        |off: usize| -> Result<u16, HostOpsError> { Ok(u16::from_be_bytes(be(body, off)?)) };
    let out = ObservationTables {
        neighbor_active: u16at(0)?,
        neighbor_total: u16at(2)?,
        route_reachable: u16at(4)?,
        route_total: u16at(6)?,
        link_sessions: u16at(8)?,
        link_cap: u16at(10)?,
        end_sessions: u16at(12)?,
        end_cap: u16at(14)?,
        dedup_resident: u16at(16)?,
        dedup_terminal: u16at(18)?,
        dedup_cap: u16at(20)?,
        tx_used: body[22],
        tx_cap: body[23],
        group_trees: body[24],
        group_origins: body[25],
        dedup_refused: u32::from_be_bytes(be(body, 26)?),
        dedup_evicted: u32::from_be_bytes(be(body, 30)?),
    };
    if u16at(34)? != 0 {
        return Err(HostOpsError::Invalid("observation tables reserved"));
    }
    Ok(out)
}

/// Join-lifecycle record singleton (44-byte body).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationMilestones {
    pub mode: u8,
    pub membership: u8,
    pub joiner_state: u8,
    pub flags: u8,
    pub attempts: u32,
    pub join_started_age_ms: u64,
    pub adopted_age_ms: u64,
    pub confirmed_age_ms: u64,
    pub adopted_node: u64,
}

impl ObservationMilestones {
    pub fn adopted(&self) -> bool {
        self.flags & MILESTONE_ADOPTED != 0
    }
    pub fn confirmed(&self) -> bool {
        self.flags & MILESTONE_CONFIRMED != 0
    }
}

pub fn encode_observation_milestones(body: &ObservationMilestones) -> Vec<u8> {
    let mut out = Vec::with_capacity(MILESTONES_BODY);
    out.push(body.mode);
    out.push(body.membership);
    out.push(body.joiner_state);
    out.push(body.flags);
    out.extend_from_slice(&body.attempts.to_be_bytes());
    out.extend_from_slice(&body.join_started_age_ms.to_be_bytes());
    out.extend_from_slice(&body.adopted_age_ms.to_be_bytes());
    out.extend_from_slice(&body.confirmed_age_ms.to_be_bytes());
    out.extend_from_slice(&body.adopted_node.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

pub fn decode_observation_milestones(body: &[u8]) -> Result<ObservationMilestones, HostOpsError> {
    if body.len() != MILESTONES_BODY {
        return Err(HostOpsError::LengthMismatch);
    }
    let out = ObservationMilestones {
        mode: body[0],
        membership: body[1],
        joiner_state: body[2],
        flags: body[3],
        attempts: u32::from_be_bytes(be(body, 4)?),
        join_started_age_ms: u64::from_be_bytes(be(body, 8)?),
        adopted_age_ms: u64::from_be_bytes(be(body, 16)?),
        confirmed_age_ms: u64::from_be_bytes(be(body, 24)?),
        adopted_node: u64::from_be_bytes(be(body, 32)?),
    };
    if u32::from_be_bytes(be(body, 40)?) != 0 {
        return Err(HostOpsError::Invalid("observation milestones reserved"));
    }
    if out.flags & !(MILESTONE_ADOPTED | MILESTONE_CONFIRMED) != 0 {
        return Err(HostOpsError::Invalid("observation milestone flags"));
    }
    Ok(out)
}

/// Topology summary singleton (24-byte body).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationSummary {
    pub neighbor_digest: u32,
    pub route_digest: u32,
    pub neighbor_active: u16,
    pub neighbor_total: u16,
    pub route_reachable: u16,
    pub route_total: u16,
    pub milestone_gen: u32,
}

pub fn encode_observation_summary(body: &ObservationSummary) -> Vec<u8> {
    let mut out = Vec::with_capacity(SUMMARY_BODY);
    out.extend_from_slice(&body.neighbor_digest.to_be_bytes());
    out.extend_from_slice(&body.route_digest.to_be_bytes());
    out.extend_from_slice(&body.neighbor_active.to_be_bytes());
    out.extend_from_slice(&body.neighbor_total.to_be_bytes());
    out.extend_from_slice(&body.route_reachable.to_be_bytes());
    out.extend_from_slice(&body.route_total.to_be_bytes());
    out.extend_from_slice(&body.milestone_gen.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

pub fn decode_observation_summary(body: &[u8]) -> Result<ObservationSummary, HostOpsError> {
    if body.len() != SUMMARY_BODY {
        return Err(HostOpsError::LengthMismatch);
    }
    let out = ObservationSummary {
        neighbor_digest: u32::from_be_bytes(be(body, 0)?),
        route_digest: u32::from_be_bytes(be(body, 4)?),
        neighbor_active: u16::from_be_bytes(be(body, 8)?),
        neighbor_total: u16::from_be_bytes(be(body, 10)?),
        route_reachable: u16::from_be_bytes(be(body, 12)?),
        route_total: u16::from_be_bytes(be(body, 14)?),
        milestone_gen: u32::from_be_bytes(be(body, 16)?),
    };
    if u32::from_be_bytes(be(body, 20)?) != 0 {
        return Err(HostOpsError::Invalid("observation summary reserved"));
    }
    Ok(out)
}

/// One selected route (30-byte entry).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteDetailEntry {
    pub destination: u64,
    pub next_hop: u64,
    pub generation: u32,
    pub sequence: u16,
    pub metric: u16,
    pub valid: bool,
    pub remaining_ms: u32,
}

pub fn encode_route_detail_entry(entry: &RouteDetailEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(ROUTE_ENTRY_SIZE);
    out.extend_from_slice(&entry.destination.to_be_bytes());
    out.extend_from_slice(&entry.next_hop.to_be_bytes());
    out.extend_from_slice(&entry.generation.to_be_bytes());
    out.extend_from_slice(&entry.sequence.to_be_bytes());
    out.extend_from_slice(&entry.metric.to_be_bytes());
    out.push(u8::from(entry.valid));
    out.push(0);
    out.extend_from_slice(&entry.remaining_ms.to_be_bytes());
    out
}

pub fn decode_route_detail_entry(entry: &[u8]) -> Result<RouteDetailEntry, HostOpsError> {
    if entry.len() != ROUTE_ENTRY_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    let flags = entry[24];
    if flags > 1 || entry[25] != 0 {
        return Err(HostOpsError::Invalid("observation route flags"));
    }
    Ok(RouteDetailEntry {
        destination: u64::from_be_bytes(be(entry, 0)?),
        next_hop: u64::from_be_bytes(be(entry, 8)?),
        generation: u32::from_be_bytes(be(entry, 16)?),
        sequence: u16::from_be_bytes(be(entry, 20)?),
        metric: u16::from_be_bytes(be(entry, 22)?),
        valid: flags == 1,
        remaining_ms: u32::from_be_bytes(be(entry, 26)?),
    })
}

/// One neighbor-table row (24-byte entry): the link the observer holds
/// toward `peer` — discovery phase, cost, RSSI evidence and the neighbor
/// lease. Unknown ages/leases read `AGE_UNKNOWN`; RSSI bytes are only
/// meaningful with their validity flag.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NeighborDetailEntry {
    pub peer: u64,
    pub heard_age_ms: u32,
    pub lease_remaining_ms: u32,
    pub link_cost: u16,
    pub rssi_ewma_q8_8: i16,
    pub phase: u8,
    pub flags: u8,
    pub rssi_last_dbm: i8,
}

impl NeighborDetailEntry {
    pub fn active(&self) -> bool {
        self.flags & NBR_ACTIVE != 0
    }
    pub fn rssi_valid(&self) -> bool {
        self.flags & NBR_RSSI_VALID != 0
    }
    pub fn heard_valid(&self) -> bool {
        self.flags & NBR_HEARD_VALID != 0
    }
}

pub fn encode_neighbor_detail_entry(entry: &NeighborDetailEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(NEIGHBOR_ENTRY_SIZE);
    out.extend_from_slice(&entry.peer.to_be_bytes());
    out.extend_from_slice(&entry.heard_age_ms.to_be_bytes());
    out.extend_from_slice(&entry.lease_remaining_ms.to_be_bytes());
    out.extend_from_slice(&entry.link_cost.to_be_bytes());
    out.extend_from_slice(&entry.rssi_ewma_q8_8.to_be_bytes());
    out.push(entry.phase);
    out.push(entry.flags);
    out.push(entry.rssi_last_dbm as u8);
    out.push(0);
    out
}

pub fn decode_neighbor_detail_entry(entry: &[u8]) -> Result<NeighborDetailEntry, HostOpsError> {
    if entry.len() != NEIGHBOR_ENTRY_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    if entry[21] & !(NBR_ACTIVE | NBR_RSSI_VALID | NBR_HEARD_VALID) != 0 || entry[23] != 0 {
        return Err(HostOpsError::Invalid("observation neighbor flags"));
    }
    Ok(NeighborDetailEntry {
        peer: u64::from_be_bytes(be(entry, 0)?),
        heard_age_ms: u32::from_be_bytes(be(entry, 8)?),
        lease_remaining_ms: u32::from_be_bytes(be(entry, 12)?),
        link_cost: u16::from_be_bytes(be(entry, 16)?),
        rssi_ewma_q8_8: i16::from_be_bytes(be(entry, 18)?),
        phase: entry[20],
        flags: entry[21],
        rssi_last_dbm: entry[22] as i8,
    })
}

fn singleton_body(section: u8) -> usize {
    match section {
        SECTION_SYSTEM => SYSTEM_BODY,
        SECTION_TABLES => TABLES_BODY,
        SECTION_MILESTONES => MILESTONES_BODY,
        SECTION_SUMMARY => SUMMARY_BODY,
        _ => 0,
    }
}

/// 0x71 OBSERVATION_PAGE header (26-byte fixed prefix).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationPageHeader {
    pub result: u16,
    pub section: u8,
    pub flags: u8,
    pub count: u8,
    pub boot_id: u64,
    pub revision: u32,
    pub next_after: u64,
}

fn check_page(header: &ObservationPageHeader, body_len: usize) -> Result<(), HostOpsError> {
    if !section_valid(header.section) {
        return Err(HostOpsError::Invalid("observation page section"));
    }
    if !config_result_valid(header.result) {
        return Err(HostOpsError::Invalid("observation page result"));
    }
    if header.flags & !(PAGE_MORE | PAGE_ARMED) != 0 {
        return Err(HostOpsError::Invalid("observation page flags"));
    }
    if usize::from(header.count) > PAGE_MAX {
        return Err(HostOpsError::Invalid("observation page count"));
    }
    let count = usize::from(header.count);
    if header.result != RESULT_OK {
        if count != 0 || body_len != 0 {
            return Err(HostOpsError::Invalid("observation error page"));
        }
        return Ok(());
    }
    if header.section == SECTION_ROUTES {
        if body_len != count * ROUTE_ENTRY_SIZE {
            return Err(HostOpsError::LengthMismatch);
        }
    } else if header.section == SECTION_NEIGHBORS {
        if body_len != count * NEIGHBOR_ENTRY_SIZE {
            return Err(HostOpsError::LengthMismatch);
        }
    } else {
        if count != 1 || body_len != singleton_body(header.section) {
            return Err(HostOpsError::LengthMismatch);
        }
        return Ok(());
    }
    // Paged entries must arrive strictly ascending, with the cursor on
    // the last one — checked by the caller-provided body below.
    Ok(())
}

fn check_routes_body(body: &[u8], header: &ObservationPageHeader) -> Result<(), HostOpsError> {
    let count = usize::from(header.count);
    let mut previous: Option<u64> = None;
    for i in 0..count {
        let entry = decode_route_detail_entry(&body[i * ROUTE_ENTRY_SIZE..][..ROUTE_ENTRY_SIZE])?;
        if let Some(prev) = previous {
            if entry.destination <= prev {
                return Err(HostOpsError::Invalid("observation page order"));
            }
        }
        previous = Some(entry.destination);
    }
    if let Some(last) = previous {
        if header.next_after != last {
            return Err(HostOpsError::Invalid("observation page cursor"));
        }
    }
    Ok(())
}

fn check_neighbors_body(body: &[u8], header: &ObservationPageHeader) -> Result<(), HostOpsError> {
    let count = usize::from(header.count);
    let mut previous: Option<u64> = None;
    for i in 0..count {
        let entry =
            decode_neighbor_detail_entry(&body[i * NEIGHBOR_ENTRY_SIZE..][..NEIGHBOR_ENTRY_SIZE])?;
        if let Some(prev) = previous {
            if entry.peer <= prev {
                return Err(HostOpsError::Invalid("observation page order"));
            }
        }
        previous = Some(entry.peer);
    }
    if let Some(last) = previous {
        if header.next_after != last {
            return Err(HostOpsError::Invalid("observation page cursor"));
        }
    }
    Ok(())
}

pub fn encode_observation_page(
    header: &ObservationPageHeader,
    body: &[u8],
) -> Result<Vec<u8>, HostOpsError> {
    check_page(header, body.len())?;
    if header.result == RESULT_OK && header.section == SECTION_ROUTES {
        check_routes_body(body, header)?;
    }
    if header.result == RESULT_OK && header.section == SECTION_NEIGHBORS {
        check_neighbors_body(body, header)?;
    }
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + PAGE_FIXED + body.len());
    head(&mut out, SUB_OBSERVATION_PAGE, PAGE_FIXED + body.len());
    out.extend_from_slice(&header.result.to_be_bytes());
    out.push(header.section);
    out.push(header.flags);
    out.push(header.count);
    out.push(0);
    out.extend_from_slice(&header.boot_id.to_be_bytes());
    out.extend_from_slice(&header.revision.to_be_bytes());
    out.extend_from_slice(&header.next_after.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

pub fn decode_observation_page(
    inner: &[u8],
) -> Result<(ObservationPageHeader, Vec<u8>), HostOpsError> {
    let payload = body(inner, SUB_OBSERVATION_PAGE, PAGE_FIXED, PAGE_MAX_PAYLOAD)?;
    let header = ObservationPageHeader {
        result: u16::from_be_bytes(be(payload, 0)?),
        section: payload[2],
        flags: payload[3],
        count: payload[4],
        boot_id: u64::from_be_bytes(be(payload, 6)?),
        revision: u32::from_be_bytes(be(payload, 14)?),
        next_after: u64::from_be_bytes(be(payload, 18)?),
    };
    if payload[5] != 0 {
        return Err(HostOpsError::Invalid("observation page reserved"));
    }
    let rest = &payload[PAGE_FIXED..];
    check_page(&header, rest.len())?;
    if header.result == RESULT_OK && header.section == SECTION_ROUTES {
        check_routes_body(rest, &header)?;
    }
    if header.result == RESULT_OK && header.section == SECTION_NEIGHBORS {
        check_neighbors_body(rest, &header)?;
    }
    Ok((header, rest.to_vec()))
}

/// 0x72 OBSERVATION_EVENT (G→H, unsolicited).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationEvent {
    /// 1-based per arm; a gap means lost events — the host re-pulls.
    pub sequence: u32,
    pub kind: u8,
    pub mask: u8,
    pub boot_id: u64,
    /// Topology: route digest. Milestone: milestone generation.
    pub revision: u32,
    /// Topology: neighbor digest. Milestone: 0.
    pub extra: u32,
}

fn check_event(event: &ObservationEvent) -> Result<(), HostOpsError> {
    if event.sequence == 0 {
        return Err(HostOpsError::Invalid("observation event sequence"));
    }
    match event.kind {
        EVENT_TOPOLOGY => {
            if event.mask & !(EVENT_MASK_NEIGHBORS | EVENT_MASK_ROUTES) != 0 {
                return Err(HostOpsError::Invalid("observation event mask"));
            }
        }
        EVENT_MILESTONE => {
            if event.mask != 0 {
                return Err(HostOpsError::Invalid("observation event mask"));
            }
        }
        _ => return Err(HostOpsError::Invalid("observation event kind")),
    }
    Ok(())
}

pub fn encode_observation_event(event: &ObservationEvent) -> Result<Vec<u8>, HostOpsError> {
    check_event(event)?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + EVENT_PAYLOAD);
    head(&mut out, SUB_OBSERVATION_EVENT, EVENT_PAYLOAD);
    out.extend_from_slice(&event.sequence.to_be_bytes());
    out.push(event.kind);
    out.push(event.mask);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&event.boot_id.to_be_bytes());
    out.extend_from_slice(&event.revision.to_be_bytes());
    out.extend_from_slice(&event.extra.to_be_bytes());
    Ok(out)
}

pub fn decode_observation_event(inner: &[u8]) -> Result<ObservationEvent, HostOpsError> {
    let payload = body(inner, SUB_OBSERVATION_EVENT, EVENT_PAYLOAD, EVENT_PAYLOAD)?;
    let event = ObservationEvent {
        sequence: u32::from_be_bytes(be(payload, 0)?),
        kind: payload[4],
        mask: payload[5],
        boot_id: u64::from_be_bytes(be(payload, 8)?),
        revision: u32::from_be_bytes(be(payload, 16)?),
        extra: u32::from_be_bytes(be(payload, 20)?),
    };
    if u16::from_be_bytes(be(payload, 6)?) != 0 {
        return Err(HostOpsError::Invalid("observation event reserved"));
    }
    check_event(&event)?;
    Ok(event)
}

// --- Remote observation (observation_v1 over Diagnostic 0x30/0x31) ---
//
// A gateway forwards one observer's 0x70-shaped question to a mesh peer
// and relays the answer: the observer serves the SAME section bytes the
// USB 0x71 page carries (same encoders), so the daemon decodes both legs
// with one codec. Pull-only (no change notifications cross the radio);
// the 128 B reply bound pages routes 2 and neighbors 3 rows at a time.
// Byte-identical to `RemoteObservationQuery`/`RemoteObservationSnapshot`
// in `components/routeloom/{include/routeloom/telemetry.hpp,src/telemetry.cpp}`.

/// Diagnostic subtype 7 query body: prefix + request_id:u32, section:u8,
/// max_entries:u8, flags:u8, reserved:u8, after:u64, reserved:u32.
pub const REMOTE_QUERY_BODY_SIZE: usize = 24;
/// Diagnostic subtype 8 head: prefix + request_id:u32, observer:u64,
/// observer_boot:u64, section:u8, flags:u8, count:u8, reserved:u8,
/// revision:u32, sampled_ms:u64 — then the 0x71-identical section bytes.
pub const REMOTE_SNAPSHOT_HEAD_SIZE: usize = 40;
/// Largest subtype 8 body (head + section bytes), prefix included.
pub const REMOTE_SNAPSHOT_BODY_MAX: usize = 128;
/// Fixed decoder storage bound; the valid page shapes occupy at most 72 bytes.
pub const REMOTE_SECTION_MAX: usize = 96;
/// Remote page bounds (the 128 B reply bound pages routes 3 and
/// neighbors 3 rows at a time); singletons answer exactly one body.
pub const REMOTE_ROUTES_MAX: u8 = 2;
pub const REMOTE_NEIGHBORS_MAX: u8 = 3;
/// Query flags: bit0 EXACT (routes/neighbors only — `after` names one
/// destination/peer). Snapshot flags: bit0 MORE.
pub const REMOTE_QUERY_EXACT: u8 = 1 << 0;
pub const REMOTE_SNAPSHOT_MORE: u8 = 1 << 0;

/// One subtype-7 RemoteObservationQuery, validated like the device
/// encoder (`remote_observation_query_encode`): nonzero request id, a
/// known section, 1..=remote bound entries, EXACT only on paged sections
/// with a non-cursor `after`, and a non-broadcast cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteObservationQuery {
    pub request_id: u32,
    pub section: u8,
    pub max_entries: u8,
    pub flags: u8,
    pub after: u64,
}

fn remote_bound(section: u8) -> Option<u8> {
    match section {
        SECTION_ROUTES => Some(REMOTE_ROUTES_MAX),
        SECTION_NEIGHBORS => Some(REMOTE_NEIGHBORS_MAX),
        SECTION_SYSTEM | SECTION_TABLES | SECTION_MILESTONES | SECTION_SUMMARY => Some(1),
        _ => None,
    }
}

fn remote_paged(section: u8) -> bool {
    section == SECTION_ROUTES || section == SECTION_NEIGHBORS
}

pub fn encode_remote_observation_query(
    query: &RemoteObservationQuery,
) -> Result<Vec<u8>, HostOpsError> {
    let Some(bound) = remote_bound(query.section) else {
        return Err(HostOpsError::Invalid("remote query section"));
    };
    let exact = query.flags & REMOTE_QUERY_EXACT != 0;
    if query.request_id == 0
        || query.max_entries == 0
        || query.max_entries > bound
        || query.flags & !REMOTE_QUERY_EXACT != 0
        || query.after == u64::MAX
        || (exact && (!remote_paged(query.section) || query.after == 0))
    {
        return Err(HostOpsError::Invalid("remote query fields"));
    }
    let mut out = Vec::with_capacity(REMOTE_QUERY_BODY_SIZE);
    out.extend_from_slice(&[
        crate::telemetry::DIAG_BODY_VERSION,
        crate::telemetry::DIAG_SUB_REMOTE_OBSERVATION_QUERY,
        0,
        0,
    ]);
    out.extend_from_slice(&query.request_id.to_be_bytes());
    out.push(query.section);
    out.push(query.max_entries);
    out.push(query.flags);
    out.push(0);
    out.extend_from_slice(&query.after.to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    Ok(out)
}

/// One subtype-8 RemoteObservationSnapshot: the answering node's point
/// sample. `revision` carries the section digest for
/// routes/neighbors/summary and 0 for the point-sample singletons. No
/// next_after field: entries ascend like 0x71 pages, so the cursor is
/// the last entry's id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteObservationSnapshot {
    pub request_id: u32,
    pub observer: u64,
    pub observer_boot: u64,
    pub section: u8,
    pub flags: u8,
    pub count: u8,
    pub revision: u32,
    pub sampled_ms: u64,
    pub body: Vec<u8>,
}

/// Servable (section, count) shapes, mirroring
/// `observation_remote_shape`: singletons answer exactly one body, paged
/// sections up to their remote bound — count 0 with an empty body is the
/// honest absent/past-the-end page, like 0x71.
fn remote_shape(section: u8, count: u8) -> Option<usize> {
    match section {
        SECTION_SYSTEM if count == 1 => Some(SYSTEM_BODY),
        SECTION_TABLES if count == 1 => Some(TABLES_BODY),
        SECTION_MILESTONES if count == 1 => Some(MILESTONES_BODY),
        SECTION_SUMMARY if count == 1 => Some(SUMMARY_BODY),
        SECTION_ROUTES if count <= REMOTE_ROUTES_MAX => Some(count as usize * ROUTE_ENTRY_SIZE),
        SECTION_NEIGHBORS if count <= REMOTE_NEIGHBORS_MAX => {
            Some(count as usize * NEIGHBOR_ENTRY_SIZE)
        }
        _ => None,
    }
}

pub fn decode_remote_observation_snapshot(
    body: &[u8],
) -> Result<RemoteObservationSnapshot, HostOpsError> {
    if body.len() < REMOTE_SNAPSHOT_HEAD_SIZE || body.len() > REMOTE_SNAPSHOT_BODY_MAX {
        return Err(HostOpsError::LengthMismatch);
    }
    if body[0] != crate::telemetry::DIAG_BODY_VERSION
        || body[1] != crate::telemetry::DIAG_SUB_REMOTE_OBSERVATION_SNAPSHOT
        || body[2] != 0
        || body[3] != 0
    {
        return Err(HostOpsError::Invalid("remote snapshot prefix"));
    }
    let observer = u64::from_be_bytes(be(body, 8)?);
    let section = body[24];
    let flags = body[25];
    let count = body[26];
    if section > SECTION_NEIGHBORS
        || flags & !REMOTE_SNAPSHOT_MORE != 0
        || body[27] != 0
        || observer == 0
        || observer == u64::MAX
    {
        return Err(HostOpsError::Invalid("remote snapshot fields"));
    }
    let Some(want) = remote_shape(section, count) else {
        return Err(HostOpsError::Invalid("remote snapshot shape"));
    };
    if body.len() - REMOTE_SNAPSHOT_HEAD_SIZE != want {
        return Err(HostOpsError::LengthMismatch);
    }
    Ok(RemoteObservationSnapshot {
        request_id: u32::from_be_bytes(be(body, 4)?),
        observer,
        observer_boot: u64::from_be_bytes(be(body, 16)?),
        section,
        flags,
        count,
        revision: u32::from_be_bytes(be(body, 28)?),
        sampled_ms: u64::from_be_bytes(be(body, 32)?),
        body: body[REMOTE_SNAPSHOT_HEAD_SIZE..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").expect("hex fmt");
            out
        })
    }

    #[test]
    fn query_round_trip() {
        let query = ObservationQuery {
            section: SECTION_ROUTES,
            max_entries: 8,
            flags: QUERY_SUBSCRIBE,
            after: 0x0102_0304_0506_0708,
        };
        let bytes = encode_observation_query(&query).unwrap();
        assert_eq!(bytes.len(), INNER_HEAD_SIZE + QUERY_PAYLOAD);
        assert_eq!(decode_observation_query(&bytes).unwrap(), query);
    }

    #[test]
    fn query_rejects() {
        let good = ObservationQuery {
            section: SECTION_ROUTES,
            max_entries: 8,
            flags: 0,
            after: 0,
        };
        for bad in [
            ObservationQuery { section: 6, ..good },
            ObservationQuery {
                max_entries: 0,
                ..good
            },
            ObservationQuery {
                max_entries: 9,
                ..good
            },
            ObservationQuery {
                flags: 0xFC,
                ..good
            },
            ObservationQuery {
                after: u64::MAX,
                ..good
            },
            ObservationQuery {
                flags: QUERY_EXACT,
                after: 0,
                ..good
            },
            ObservationQuery {
                section: SECTION_SYSTEM,
                flags: QUERY_EXACT,
                after: 9,
                ..good
            },
        ] {
            assert!(encode_observation_query(&bad).is_err(), "{bad:?}");
        }
        let bytes = encode_observation_query(&good).unwrap();
        assert!(decode_observation_query(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn singletons_round_trip() {
        let system = ObservationSystem {
            uptime_ms: 0xFFFF_FFFF_FFFF_FFFF,
            heap_free_bytes: 1,
            heap_min_bytes: 2,
            heap_largest_bytes: 3,
            reset_code: 3,
            power_mode: 2,
            coord_mode: 2,
            sec_profile: 2,
        };
        let bytes = encode_observation_system(&system);
        assert_eq!(bytes.len(), SYSTEM_BODY);
        assert_eq!(decode_observation_system(&bytes).unwrap(), system);
        assert!(decode_observation_system(&bytes[..SYSTEM_BODY - 1]).is_err());

        let tables = ObservationTables {
            neighbor_active: 0xFFFF,
            route_total: 128,
            link_sessions: 32,
            link_cap: 32,
            dedup_resident: 96,
            dedup_terminal: 7,
            dedup_cap: 96,
            tx_used: 31,
            tx_cap: 32,
            group_trees: 4,
            group_origins: 3,
            dedup_refused: 0xFFFF_FFFF,
            dedup_evicted: 123,
            ..ObservationTables::default()
        };
        let bytes = encode_observation_tables(&tables);
        assert_eq!(bytes.len(), TABLES_BODY);
        assert_eq!(decode_observation_tables(&bytes).unwrap(), tables);

        let milestones = ObservationMilestones {
            mode: 3,
            membership: 5,
            joiner_state: 3,
            flags: MILESTONE_ADOPTED | MILESTONE_CONFIRMED,
            attempts: 2,
            join_started_age_ms: 100,
            adopted_age_ms: 365 * 24 * 60 * 60 * 1000,
            confirmed_age_ms: 10,
            adopted_node: 0x0A,
        };
        let bytes = encode_observation_milestones(&milestones);
        assert_eq!(bytes.len(), MILESTONES_BODY);
        assert_eq!(decode_observation_milestones(&bytes).unwrap(), milestones);
        let mut bad = bytes.clone();
        bad[3] = 0xFF;
        assert!(decode_observation_milestones(&bad).is_err());

        let summary = ObservationSummary {
            neighbor_digest: 0xA5A5_A5A5,
            route_digest: 0x5A5A_5A5A,
            neighbor_active: 3,
            route_total: 40,
            milestone_gen: 9,
            ..ObservationSummary::default()
        };
        let bytes = encode_observation_summary(&summary);
        assert_eq!(bytes.len(), SUMMARY_BODY);
        assert_eq!(decode_observation_summary(&bytes).unwrap(), summary);
    }

    #[test]
    fn neighbor_entry_round_trip() {
        let entry = NeighborDetailEntry {
            peer: 0x0102_0304_0506_0708,
            heard_age_ms: 4242,
            lease_remaining_ms: 80_000,
            link_cost: 12,
            rssi_ewma_q8_8: -70 * 256 + 128,
            phase: 6,
            flags: NBR_ACTIVE | NBR_RSSI_VALID | NBR_HEARD_VALID,
            rssi_last_dbm: -71,
        };
        let bytes = encode_neighbor_detail_entry(&entry);
        assert_eq!(bytes.len(), NEIGHBOR_ENTRY_SIZE);
        assert_eq!(decode_neighbor_detail_entry(&bytes).unwrap(), entry);
        // Unknown lease/heard read as the sentinel with validity cleared.
        let unknown = NeighborDetailEntry {
            peer: 9,
            heard_age_ms: AGE_UNKNOWN,
            lease_remaining_ms: AGE_UNKNOWN,
            link_cost: 0xFFFF,
            phase: PHASE_UNKNOWN,
            ..NeighborDetailEntry::default()
        };
        let bytes = encode_neighbor_detail_entry(&unknown);
        assert_eq!(decode_neighbor_detail_entry(&bytes).unwrap(), unknown);
        let mut bad = bytes.clone();
        bad[21] = 0xF8;
        assert!(decode_neighbor_detail_entry(&bad).is_err());
        let mut bad = bytes.clone();
        bad[23] = 1;
        assert!(decode_neighbor_detail_entry(&bad).is_err());
    }

    #[test]
    fn neighbors_page_orders_and_cursors_like_routes() {
        let e1 = NeighborDetailEntry {
            peer: 2,
            ..NeighborDetailEntry::default()
        };
        let e2 = NeighborDetailEntry {
            peer: 3,
            ..NeighborDetailEntry::default()
        };
        let mut body = encode_neighbor_detail_entry(&e1);
        body.extend_from_slice(&encode_neighbor_detail_entry(&e2));
        let header = ObservationPageHeader {
            result: RESULT_OK,
            section: SECTION_NEIGHBORS,
            flags: PAGE_MORE,
            count: 2,
            boot_id: 9,
            revision: 0xA5A5_A5A5,
            next_after: 3,
        };
        let bytes = encode_observation_page(&header, &body).unwrap();
        let (back, _) = decode_observation_page(&bytes).unwrap();
        assert_eq!(back.count, 2);
        // Non-ascending peers and a wrong cursor are rejected.
        let mut swapped = encode_neighbor_detail_entry(&e2);
        swapped.extend_from_slice(&encode_neighbor_detail_entry(&e1));
        assert!(encode_observation_page(&header, &swapped).is_err());
        let bad_cursor = ObservationPageHeader {
            next_after: 2,
            ..header
        };
        assert!(encode_observation_page(&bad_cursor, &body).is_err());
        // EXACT names one neighbor like one route.
        let exact = ObservationQuery {
            section: SECTION_NEIGHBORS,
            max_entries: 1,
            flags: QUERY_EXACT,
            after: 7,
        };
        assert!(encode_observation_query(&exact).is_ok());
    }

    #[test]
    fn route_entry_round_trip() {
        let entry = RouteDetailEntry {
            destination: 0x0102_0304_0506_0708,
            next_hop: 0x0807_0605_0403_0201,
            generation: 0xA5A5_A5A5,
            sequence: 0x1234,
            metric: 0x7FFF,
            valid: true,
            remaining_ms: 0xDEAD_BEEF,
        };
        let bytes = encode_route_detail_entry(&entry);
        assert_eq!(bytes.len(), ROUTE_ENTRY_SIZE);
        assert_eq!(decode_route_detail_entry(&bytes).unwrap(), entry);
        let mut bad = bytes.clone();
        bad[24] = 2;
        assert!(decode_route_detail_entry(&bad).is_err());
        let mut bad = bytes.clone();
        bad[25] = 1;
        assert!(decode_route_detail_entry(&bad).is_err());
    }

    #[test]
    fn page_round_trip_and_rejects() {
        let system = ObservationSystem {
            uptime_ms: 4242,
            ..ObservationSystem::default()
        };
        let body = encode_observation_system(&system);
        let header = ObservationPageHeader {
            result: RESULT_OK,
            section: SECTION_SYSTEM,
            flags: PAGE_ARMED,
            count: 1,
            boot_id: 0x00B0_071D_0001,
            revision: 0,
            next_after: 0,
        };
        let bytes = encode_observation_page(&header, &body).unwrap();
        let (back, rest) = decode_observation_page(&bytes).unwrap();
        assert_eq!(back, header);
        assert_eq!(rest, body);

        let e1 = RouteDetailEntry {
            destination: 2,
            next_hop: 2,
            generation: 1,
            valid: true,
            remaining_ms: 500,
            ..RouteDetailEntry::default()
        };
        let e2 = RouteDetailEntry {
            destination: 3,
            next_hop: 2,
            generation: 1,
            valid: true,
            remaining_ms: 400,
            ..RouteDetailEntry::default()
        };
        let mut routes = encode_route_detail_entry(&e1);
        routes.extend_from_slice(&encode_route_detail_entry(&e2));
        let routes_header = ObservationPageHeader {
            result: RESULT_OK,
            section: SECTION_ROUTES,
            flags: PAGE_MORE | PAGE_ARMED,
            count: 2,
            boot_id: 9,
            revision: 0x1122_3344,
            next_after: 3,
        };
        let bytes = encode_observation_page(&routes_header, &routes).unwrap();
        let (back, _) = decode_observation_page(&bytes).unwrap();
        assert_eq!(back.count, 2);

        // Count/body mismatch, bad cursor, non-ascending entries.
        let short = routes[..ROUTE_ENTRY_SIZE].to_vec();
        assert!(encode_observation_page(&routes_header, &short).is_err());
        let bad_cursor = ObservationPageHeader {
            next_after: 2,
            ..routes_header
        };
        assert!(encode_observation_page(&bad_cursor, &routes).is_err());
        let mut swapped = encode_route_detail_entry(&e2);
        swapped.extend_from_slice(&encode_route_detail_entry(&e1));
        assert!(encode_observation_page(&routes_header, &swapped).is_err());

        // Non-Ok pages carry count 0 and an empty body, any section.
        let unsupported = ObservationPageHeader {
            result: RESULT_UNSUPPORTED,
            section: SECTION_TABLES,
            boot_id: 9,
            next_after: 0x77,
            ..ObservationPageHeader::default()
        };
        let bytes = encode_observation_page(&unsupported, &[]).unwrap();
        let (back, rest) = decode_observation_page(&bytes).unwrap();
        assert_eq!(back.count, 0);
        assert!(rest.is_empty());
        let bad = ObservationPageHeader {
            result: RESULT_UNSUPPORTED,
            section: SECTION_TABLES,
            count: 1,
            ..ObservationPageHeader::default()
        };
        assert!(encode_observation_page(&bad, &[]).is_err());
    }

    #[test]
    fn event_round_trip_and_rejects() {
        let event = ObservationEvent {
            sequence: 41,
            kind: EVENT_TOPOLOGY,
            mask: EVENT_MASK_ROUTES,
            boot_id: 0x00B0_071D_0001,
            revision: 0x1111_1111,
            extra: 0x2222_2222,
        };
        let bytes = encode_observation_event(&event).unwrap();
        assert_eq!(bytes.len(), INNER_HEAD_SIZE + EVENT_PAYLOAD);
        assert_eq!(decode_observation_event(&bytes).unwrap(), event);

        for bad in [
            ObservationEvent {
                sequence: 0,
                ..event
            },
            ObservationEvent { kind: 3, ..event },
            ObservationEvent {
                mask: 0xFC,
                ..event
            },
            ObservationEvent {
                kind: EVENT_MILESTONE,
                mask: 1,
                ..event
            },
        ] {
            assert!(encode_observation_event(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn registry_names() {
        assert_eq!(reset_name(1), "power_on");
        assert_eq!(reset_name(0), "unknown");
        assert_eq!(reset_name(99), "unknown");
        assert_eq!(power_name(1), "running");
        assert_eq!(coord_mode_name(3), "member");
        assert_eq!(profile_name(2), "dev_ram");
        assert_eq!(profile_name(3), "unknown");
        assert_eq!(membership_name(5), "member");
        assert_eq!(joiner_name(2), "active");
        assert_eq!(joiner_name(0), "unknown");
    }

    // Fixed vectors dumped from the C++ device encoder (same bytes are
    // asserted in tests/cpp/test_observation.cpp `test_fixed_vectors`):
    // identical bytes must decode identically on both sides. Regenerate
    // both from the encoder — never hand-edit these.
    #[test]
    fn fixed_vectors_match_device_encoder() {
        // 0x70 routes query: section=4, flags=SUBSCRIBE, max=8, after=0.
        let query = hex_decode("0170000c040108000000000000000000");
        let decoded = decode_observation_query(&query).unwrap();
        assert_eq!(decoded.section, SECTION_ROUTES);
        assert_eq!(decoded.flags, QUERY_SUBSCRIBE);
        assert_eq!(decoded.max_entries, 8);
        assert_eq!(decoded.after, 0);

        // 0x71 system page: Ok, ARMED, count 1, boot 0xB0071D0001.
        let page = hex_decode(
            "01710036000000020100000000b0071d000100000000000000000000000000000000\
             000010920000000100000002000000030302020200000000",
        );
        let (header, body) = decode_observation_page(&page).unwrap();
        assert_eq!(header.result, RESULT_OK);
        assert_eq!(header.section, SECTION_SYSTEM);
        assert_eq!(header.count, 1);
        assert_eq!(header.boot_id, 0x00B0_071D_0001);
        let system = decode_observation_system(&body).unwrap();
        assert_eq!(system.uptime_ms, 4242);
        assert_eq!(system.heap_free_bytes, 1);
        assert_eq!(system.heap_min_bytes, 2);
        assert_eq!(system.heap_largest_bytes, 3);
        assert_eq!(system.reset_code, 3);
        assert_eq!(system.power_mode, 2);
        assert_eq!(
            hex(&encode_observation_page(&header, &body).unwrap()),
            hex(&page)
        );

        // 0x71 milestones page: member/ready, adopted+confirmed, gen 7.
        let page = hex_decode(
            "01710046000002000100000000b0071d000100000007000000000000000003050303\
             0000000200000000000000640000000000000032000000000000000a\
             000000000000000a00000000",
        );
        let (header, body) = decode_observation_page(&page).unwrap();
        assert_eq!(header.section, SECTION_MILESTONES);
        assert_eq!(header.revision, 7);
        let milestones = decode_observation_milestones(&body).unwrap();
        assert_eq!(milestones.mode, 3);
        assert_eq!(milestones.membership, 5);
        assert_eq!(milestones.flags, MILESTONE_ADOPTED | MILESTONE_CONFIRMED);
        assert!(milestones.adopted() && milestones.confirmed());
        assert_eq!(milestones.attempts, 2);
        assert_eq!(milestones.join_started_age_ms, 100);
        assert_eq!(milestones.adopted_age_ms, 50);
        assert_eq!(milestones.confirmed_age_ms, 10);
        assert_eq!(milestones.adopted_node, 0x0A);
        assert_eq!(
            hex(&encode_observation_page(&header, &body).unwrap()),
            hex(&page)
        );

        // 0x71 routes page: two ascending entries, MORE|ARMED.
        let page = hex_decode(
            "017100560000040302000000000000000009112233440000000000000003\
             0000000000000002000000000000000200000001000900010100000001f4\
             000000000000000300000000000000020000000100070002010000000190",
        );
        let (header, body) = decode_observation_page(&page).unwrap();
        assert_eq!(header.section, SECTION_ROUTES);
        assert_eq!(header.count, 2);
        assert_eq!(header.revision, 0x1122_3344);
        assert_eq!(header.next_after, 3);
        let e0 = decode_route_detail_entry(&body[..ROUTE_ENTRY_SIZE]).unwrap();
        let e1 = decode_route_detail_entry(&body[ROUTE_ENTRY_SIZE..]).unwrap();
        assert_eq!(
            (e0.destination, e0.next_hop, e0.sequence, e0.metric),
            (2, 2, 9, 1)
        );
        assert_eq!(e0.generation, 1);
        assert!(e0.valid);
        assert_eq!(e0.remaining_ms, 500);
        assert_eq!(
            (e1.destination, e1.next_hop, e1.sequence, e1.metric),
            (3, 2, 7, 2)
        );
        assert_eq!(e1.remaining_ms, 400);
        assert_eq!(
            hex(&encode_observation_page(&header, &body).unwrap()),
            hex(&page)
        );

        // 0x71 neighbors page: one row, phase reachable, lease 80 s.
        let page = hex_decode(
            "01710032000005000100000000b0071d0001a5a5a5a50000000000000002\
             000000000000000200000078000138800001ba800605b900",
        );
        let (header, body) = decode_observation_page(&page).unwrap();
        assert_eq!(header.section, SECTION_NEIGHBORS);
        assert_eq!(header.count, 1);
        assert_eq!(header.revision, 0xA5A5_A5A5);
        assert_eq!(header.next_after, 2);
        let n0 = decode_neighbor_detail_entry(&body).unwrap();
        assert_eq!(n0.peer, 2);
        assert_eq!((n0.heard_age_ms, n0.lease_remaining_ms), (120, 80_000));
        assert_eq!(n0.link_cost, 1);
        assert_eq!(n0.phase, 6);
        assert_eq!(neighbor_phase_name(n0.phase), "reachable");
        assert!(n0.active() && n0.heard_valid() && !n0.rssi_valid());
        assert_eq!(n0.rssi_last_dbm, -71);
        assert_eq!(
            hex(&encode_observation_page(&header, &body).unwrap()),
            hex(&page)
        );

        // 0x72 topology event: seq 41, kind 1, mask routes, digests.
        let event = hex_decode("017200180000002901020000000000b0071d00011111111122222222");
        let decoded = decode_observation_event(&event).unwrap();
        assert_eq!(decoded.sequence, 41);
        assert_eq!(decoded.kind, EVENT_TOPOLOGY);
        assert_eq!(decoded.mask, EVENT_MASK_ROUTES);
        assert_eq!(decoded.boot_id, 0x00B0_071D_0001);
        assert_eq!(decoded.revision, 0x1111_1111);
        assert_eq!(decoded.extra, 0x2222_2222);
        assert_eq!(
            hex(&encode_observation_event(&decoded).unwrap()),
            hex(&event)
        );
    }

    fn hex_decode(hex_str: &str) -> Vec<u8> {
        let clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    // C++-encoded (`components/routeloom/src/telemetry.cpp`) oracle vectors.
    const REMOTE_QUERY_HEX: &str = "01070000a1b2c3d405030100000000000000000900000000";
    const REMOTE_SNAPSHOT_HEX: &str = "01080000010203040000000000000abc112233445566778805010100a5a5a5a500000000000003e800000000000000020000007800013880000100000607b900";

    #[test]
    fn remote_query_encodes_the_cpp_layout() {
        let query = RemoteObservationQuery {
            request_id: 0xA1B2_C3D4,
            section: SECTION_NEIGHBORS,
            max_entries: 3,
            flags: REMOTE_QUERY_EXACT,
            after: 9,
        };
        assert_eq!(
            hex(&encode_remote_observation_query(&query).unwrap()),
            REMOTE_QUERY_HEX
        );

        // The device encoder's validation, mirrored: zero id, unknown
        // section, over-bound count, stray flags, broadcast cursor and
        // EXACT on a singleton all fail before any byte is emitted.
        let bad = [
            RemoteObservationQuery {
                request_id: 0,
                ..query
            },
            RemoteObservationQuery {
                section: 6,
                ..query
            },
            RemoteObservationQuery {
                max_entries: 4,
                ..query
            },
            RemoteObservationQuery {
                max_entries: 0,
                ..query
            },
            RemoteObservationQuery {
                flags: 0x02,
                ..query
            },
            RemoteObservationQuery {
                after: u64::MAX,
                ..query
            },
            RemoteObservationQuery {
                section: SECTION_SYSTEM,
                max_entries: 1,
                ..query
            },
        ];
        for q in bad {
            assert!(encode_remote_observation_query(&q).is_err());
        }
        // EXACT on a paged section with a cursor id is the one legal shape.
        assert!(encode_remote_observation_query(&query).is_ok());
        let page = RemoteObservationQuery {
            flags: 0,
            after: 9,
            ..query
        };
        assert!(encode_remote_observation_query(&page).is_ok());
    }

    #[test]
    fn remote_snapshot_decodes_the_cpp_layout() {
        let body = hex_decode(REMOTE_SNAPSHOT_HEX);
        let snapshot = decode_remote_observation_snapshot(&body).unwrap();
        assert_eq!(snapshot.request_id, 0x0102_0304);
        assert_eq!(snapshot.observer, 0x0abc);
        assert_eq!(snapshot.observer_boot, 0x1122_3344_5566_7788);
        assert_eq!(snapshot.section, SECTION_NEIGHBORS);
        assert_eq!(snapshot.flags, REMOTE_SNAPSHOT_MORE);
        assert_eq!(snapshot.count, 1);
        assert_eq!(snapshot.revision, 0xA5A5_A5A5);
        assert_eq!(snapshot.sampled_ms, 1_000);
        // The section bytes are the 0x71 neighbor entry verbatim — the
        // local page codec decodes the remote leg unchanged.
        let entry = decode_neighbor_detail_entry(&snapshot.body).unwrap();
        assert_eq!(entry.peer, 2);
        assert_eq!(
            (entry.heard_age_ms, entry.lease_remaining_ms),
            (120, 80_000)
        );
        assert_eq!(entry.phase, 6);

        // Shape violations fail: singleton count, over-bound page, short
        // body, stray flags, reserved observer.
        let mut bad = body.clone();
        bad[25] = 0x02;
        assert!(decode_remote_observation_snapshot(&bad).is_err());
        let mut bad = body.clone();
        bad[26] = 2;
        assert!(decode_remote_observation_snapshot(&bad).is_err());
        assert!(decode_remote_observation_snapshot(&body[..body.len() - 1]).is_err());
        let mut bad = body.clone();
        bad[24] = SECTION_SYSTEM;
        assert!(decode_remote_observation_snapshot(&bad).is_err());
    }
}
