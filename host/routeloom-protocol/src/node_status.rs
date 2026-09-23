//! node_status_v1 HostOps codec (subcommands 0x40-0x42): paginated per-node
//! link/route snapshots and unsolicited join/leave/route-change events.
//! Byte-identical to the device side in
//! `components/routeloom/{include/routeloom/usb_host_ops.hpp,src/usb_host_ops.cpp}`
//! and `include/routeloom/node_status.hpp`; the shared vectors under
//! `protocol/usb-golden/node-status` pin both.
//!
//! Inner common form (the gateway/config family shape): schema:u8=1,
//! sub:u8, payload_len:u16, payload — big-endian, exact length only.
//!
//! Clock domain: the device never sends absolute timestamps here. Every
//! age (`heard_age_ms`) is a duration on the device monotonic clock at
//! snapshot time; a host derives its own `last_heard` as
//! `host_receive_time - heard_age_ms` (an upper bound on freshness, USB
//! latency included).

use crate::host_ops::{ConfigOpsResult, HostOpsError, HOST_OPS_SCHEMA};

/// HelloAck capability bit: the device serves 0x40-0x42.
pub const CAP_NODE_STATUS_V1: u32 = 1 << 6;

pub const SUB_NODE_STATUS_QUERY: u8 = 0x40;
pub const SUB_NODE_STATUS_PAGE: u8 = 0x41;
pub const SUB_NODE_EVENT: u8 = 0x42;

pub const INNER_HEAD_SIZE: usize = 4;
pub const QUERY_PAYLOAD: usize = 10;
pub const ENTRY_SIZE: usize = 28;
pub const PAGE_FIXED: usize = 16;
/// Device page buffer bound (kNodeStatusPageMax).
pub const PAGE_MAX: usize = 16;
pub const PAGE_MAX_PAYLOAD: usize = PAGE_FIXED + PAGE_MAX * ENTRY_SIZE;
pub const EVENT_PAYLOAD: usize = 6 + ENTRY_SIZE;

pub const QUERY_SUBSCRIBE: u8 = 0x01;
pub const PAGE_MORE: u8 = 0x01;
pub const PAGE_ARMED: u8 = 0x02;

pub const FLAG_NEIGHBOR: u8 = 1 << 0;
pub const FLAG_NEIGHBOR_ACTIVE: u8 = 1 << 1;
pub const FLAG_REACHABLE: u8 = 1 << 2;
pub const FLAG_DIRECT: u8 = 1 << 3;
pub const FLAG_RSSI_VALID: u8 = 1 << 4;
pub const FLAG_HEARD_VALID: u8 = 1 << 5;
pub const FLAG_TELEMETRY_STALE: u8 = 1 << 6;
const FLAGS_MASK: u8 = 0x7F;

/// Route/link metric value meaning "none" (kInfiniteRouteMetric).
pub const INFINITE_METRIC: u16 = u16::MAX;

fn reserved_id(value: u64) -> bool {
    value == 0 || value == u64::MAX
}

/// The sub byte of a node-status inner body (0x40-0x42), if it is one.
/// Lets the daemon's frame router peel this family off the dispatcher lane.
pub fn node_status_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    matches!(
        inner[1],
        SUB_NODE_STATUS_QUERY | SUB_NODE_STATUS_PAGE | SUB_NODE_EVENT
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

/// 0x40 NODE_STATUS_QUERY (H→G).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeStatusQuery {
    /// Exclusive NodeId cursor (0 = from the start).
    pub after: u64,
    /// 1..=PAGE_MAX.
    pub max_entries: u8,
    /// QUERY_SUBSCRIBE (re)arms the device event stream for this session.
    pub flags: u8,
}

fn check_query(query: &NodeStatusQuery) -> Result<(), HostOpsError> {
    if query.after == u64::MAX {
        return Err(HostOpsError::Invalid("after"));
    }
    if query.max_entries == 0 || usize::from(query.max_entries) > PAGE_MAX {
        return Err(HostOpsError::Invalid("max_entries"));
    }
    if query.flags & !QUERY_SUBSCRIBE != 0 {
        return Err(HostOpsError::Invalid("query flags"));
    }
    Ok(())
}

pub fn encode_node_status_query(query: &NodeStatusQuery) -> Result<Vec<u8>, HostOpsError> {
    check_query(query)?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + QUERY_PAYLOAD);
    head(&mut out, SUB_NODE_STATUS_QUERY, QUERY_PAYLOAD);
    out.extend_from_slice(&query.after.to_be_bytes());
    out.push(query.max_entries);
    out.push(query.flags);
    Ok(out)
}

pub fn decode_node_status_query(inner: &[u8]) -> Result<NodeStatusQuery, HostOpsError> {
    let payload = body(inner, SUB_NODE_STATUS_QUERY, QUERY_PAYLOAD, QUERY_PAYLOAD)?;
    let query = NodeStatusQuery {
        after: u64::from_be_bytes(be(payload, 0)?),
        max_entries: payload[8],
        flags: payload[9],
    };
    check_query(&query)?;
    Ok(query)
}

/// One node as the attached gateway currently sees it (28-byte entry).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodeStatusEntry {
    pub node: u64,
    pub flags: u8,
    pub rssi_last_dbm: i8,
    /// Signed Q8.8 EWMA of RSSI (dBm * 256).
    pub rssi_ewma_q8_8: i16,
    /// Effective link cost (INFINITE_METRIC when not an active neighbor).
    pub link_cost: u16,
    /// Selected route metric (INFINITE_METRIC when unreachable).
    pub route_metric: u16,
    /// Selected next hop (0 when unreachable).
    pub next_hop: u64,
    /// Device-monotonic age of the last authenticated frame from the node.
    pub heard_age_ms: u32,
}

impl NodeStatusEntry {
    pub fn neighbor(&self) -> bool {
        self.flags & FLAG_NEIGHBOR != 0
    }
    pub fn neighbor_active(&self) -> bool {
        self.flags & FLAG_NEIGHBOR_ACTIVE != 0
    }
    pub fn reachable(&self) -> bool {
        self.flags & FLAG_REACHABLE != 0
    }
    pub fn direct(&self) -> bool {
        self.flags & FLAG_DIRECT != 0
    }
    pub fn rssi_valid(&self) -> bool {
        self.flags & FLAG_RSSI_VALID != 0
    }
    pub fn heard_valid(&self) -> bool {
        self.flags & FLAG_HEARD_VALID != 0
    }
    pub fn telemetry_stale(&self) -> bool {
        self.flags & FLAG_TELEMETRY_STALE != 0
    }
    /// RSSI EWMA in dBm (None without a measurement).
    pub fn rssi_ewma_dbm(&self) -> Option<f64> {
        self.rssi_valid()
            .then(|| f64::from(self.rssi_ewma_q8_8) / 256.0)
    }

    fn validate(&self) -> Result<(), HostOpsError> {
        if reserved_id(self.node) {
            return Err(HostOpsError::Invalid("entry node"));
        }
        if self.flags & !FLAGS_MASK != 0 {
            return Err(HostOpsError::Invalid("entry flags"));
        }
        if self.reachable() == reserved_id(self.next_hop) {
            return Err(HostOpsError::Invalid("entry next_hop"));
        }
        if !self.reachable() && self.direct() {
            return Err(HostOpsError::Invalid("entry direct"));
        }
        Ok(())
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.node.to_be_bytes());
        out.push(self.flags);
        out.push(self.rssi_last_dbm as u8);
        out.extend_from_slice(&self.rssi_ewma_q8_8.to_be_bytes());
        out.extend_from_slice(&self.link_cost.to_be_bytes());
        out.extend_from_slice(&self.route_metric.to_be_bytes());
        let next_hop = if self.reachable() { self.next_hop } else { 0 };
        out.extend_from_slice(&next_hop.to_be_bytes());
        out.extend_from_slice(&self.heard_age_ms.to_be_bytes());
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HostOpsError> {
        if bytes.len() != ENTRY_SIZE {
            return Err(HostOpsError::LengthMismatch);
        }
        let entry = Self {
            node: u64::from_be_bytes(be(bytes, 0)?),
            flags: bytes[8],
            rssi_last_dbm: bytes[9] as i8,
            rssi_ewma_q8_8: i16::from_be_bytes(be(bytes, 10)?),
            link_cost: u16::from_be_bytes(be(bytes, 12)?),
            route_metric: u16::from_be_bytes(be(bytes, 14)?),
            next_hop: u64::from_be_bytes(be(bytes, 16)?),
            heard_age_ms: u32::from_be_bytes(be(bytes, 24)?),
        };
        entry.validate()?;
        Ok(entry)
    }
}

/// 0x41 NODE_STATUS_PAGE (G→H reply under the query's request id).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStatusPage {
    /// ConfigOpsResult space (Ok / Unsupported).
    pub result: u16,
    pub flags: u8,
    pub next_after: u64,
    /// Last event sequence the device issued in this session (0 = none).
    pub event_seq: u32,
    pub entries: Vec<NodeStatusEntry>,
}

impl NodeStatusPage {
    pub fn more(&self) -> bool {
        self.flags & PAGE_MORE != 0
    }
    pub fn armed(&self) -> bool {
        self.flags & PAGE_ARMED != 0
    }
    pub fn ok(&self) -> bool {
        self.result == ConfigOpsResult::Ok as u16
    }

    fn validate(&self) -> Result<(), HostOpsError> {
        ConfigOpsResult::try_from_u16(self.result)?;
        if self.flags & !(PAGE_MORE | PAGE_ARMED) != 0 {
            return Err(HostOpsError::Invalid("page flags"));
        }
        if self.entries.len() > PAGE_MAX {
            return Err(HostOpsError::Invalid("page count"));
        }
        if !self.ok() && !self.entries.is_empty() {
            return Err(HostOpsError::Invalid("entries on a failed page"));
        }
        for pair in self.entries.windows(2) {
            if pair[1].node <= pair[0].node {
                return Err(HostOpsError::Invalid("page order"));
            }
        }
        if let Some(last) = self.entries.last() {
            if self.next_after != last.node {
                return Err(HostOpsError::Invalid("page cursor"));
            }
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

pub fn encode_node_status_page(page: &NodeStatusPage) -> Result<Vec<u8>, HostOpsError> {
    page.validate()?;
    let payload_len = PAGE_FIXED + page.entries.len() * ENTRY_SIZE;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + payload_len);
    head(&mut out, SUB_NODE_STATUS_PAGE, payload_len);
    out.extend_from_slice(&page.result.to_be_bytes());
    out.push(page.flags);
    out.push(page.entries.len() as u8);
    out.extend_from_slice(&page.next_after.to_be_bytes());
    out.extend_from_slice(&page.event_seq.to_be_bytes());
    for entry in &page.entries {
        entry.encode_into(&mut out);
    }
    Ok(out)
}

pub fn decode_node_status_page(inner: &[u8]) -> Result<NodeStatusPage, HostOpsError> {
    let payload = body(inner, SUB_NODE_STATUS_PAGE, PAGE_FIXED, PAGE_MAX_PAYLOAD)?;
    let count = usize::from(payload[3]);
    if count > PAGE_MAX || payload.len() != PAGE_FIXED + count * ENTRY_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    let entries = payload[PAGE_FIXED..]
        .chunks_exact(ENTRY_SIZE)
        .map(NodeStatusEntry::decode)
        .collect::<Result<Vec<_>, _>>()?;
    let page = NodeStatusPage {
        result: u16::from_be_bytes(be(payload, 0)?),
        flags: payload[2],
        next_after: u64::from_be_bytes(be(payload, 4)?),
        event_seq: u32::from_be_bytes(be(payload, 12)?),
        entries,
    };
    page.validate()?;
    Ok(page)
}

/// Event kinds (NodeEventKind on the device).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum NodeEventKind {
    NeighborUp = 1,
    NeighborDown = 2,
    /// A feasible route to the node is selected — the node joined.
    RouteUp = 3,
    /// No feasible route remains — the node left.
    RouteDown = 4,
    /// Still reachable, the selected next hop moved.
    RouteChanged = 5,
}

impl NodeEventKind {
    pub fn try_from_byte(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            1 => Self::NeighborUp,
            2 => Self::NeighborDown,
            3 => Self::RouteUp,
            4 => Self::RouteDown,
            5 => Self::RouteChanged,
            _ => return Err(HostOpsError::UnknownEnum("node_event_kind", value)),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NeighborUp => "neighbor_up",
            Self::NeighborDown => "neighbor_down",
            Self::RouteUp => "route_up",
            Self::RouteDown => "route_down",
            Self::RouteChanged => "route_changed",
        }
    }
}

/// 0x42 NODE_EVENT (G→H, unsolicited, request id 0).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeEvent {
    /// 1-based and contiguous per subscription arm; a gap means the host
    /// missed events and must resync by paging.
    pub sequence: u32,
    pub kind: NodeEventKind,
    pub status: NodeStatusEntry,
}

pub fn encode_node_event(event: &NodeEvent) -> Result<Vec<u8>, HostOpsError> {
    if event.sequence == 0 {
        return Err(HostOpsError::Invalid("event sequence"));
    }
    event.status.validate()?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + EVENT_PAYLOAD);
    head(&mut out, SUB_NODE_EVENT, EVENT_PAYLOAD);
    out.extend_from_slice(&event.sequence.to_be_bytes());
    out.push(event.kind as u8);
    out.push(0);
    event.status.encode_into(&mut out);
    Ok(out)
}

pub fn decode_node_event(inner: &[u8]) -> Result<NodeEvent, HostOpsError> {
    let payload = body(inner, SUB_NODE_EVENT, EVENT_PAYLOAD, EVENT_PAYLOAD)?;
    let sequence = u32::from_be_bytes(be(payload, 0)?);
    if sequence == 0 {
        return Err(HostOpsError::Invalid("event sequence"));
    }
    let kind = NodeEventKind::try_from_byte(payload[4])?;
    if payload[5] != 0 {
        return Err(HostOpsError::Invalid("event reserved"));
    }
    Ok(NodeEvent {
        sequence,
        kind,
        status: NodeStatusEntry::decode(&payload[6..])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(node: u64, reachable: bool) -> NodeStatusEntry {
        NodeStatusEntry {
            node,
            flags: FLAG_NEIGHBOR
                | FLAG_NEIGHBOR_ACTIVE
                | FLAG_RSSI_VALID
                | FLAG_HEARD_VALID
                | if reachable {
                    FLAG_REACHABLE | FLAG_DIRECT
                } else {
                    0
                },
            rssi_last_dbm: -71,
            rssi_ewma_q8_8: -18000,
            link_cost: 3,
            route_metric: if reachable { 3 } else { INFINITE_METRIC },
            next_hop: if reachable { node } else { 0 },
            heard_age_ms: 1234,
        }
    }

    #[test]
    fn query_layout_matches_the_device_codec() {
        let query = NodeStatusQuery {
            after: 0x0102_0304_0506_0708,
            max_entries: 16,
            flags: QUERY_SUBSCRIBE,
        };
        let bytes = encode_node_status_query(&query).unwrap();
        // Same bytes as tests/cpp/test_node_status.cpp test_codec_query.
        assert_eq!(
            bytes,
            [0x01, 0x40, 0x00, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x01]
        );
        assert_eq!(decode_node_status_query(&bytes).unwrap(), query);
        for (index, value) in [(12, 0), (12, 17), (13, 2), (0, 2), (1, 0x41), (3, 0x0b)] {
            let mut bad = bytes.clone();
            bad[index] = value;
            assert!(decode_node_status_query(&bad).is_err(), "{index}={value}");
        }
        assert!(decode_node_status_query(&bytes[..13]).is_err());
        assert!(encode_node_status_query(&NodeStatusQuery {
            max_entries: 0,
            ..query
        })
        .is_err());
        assert!(encode_node_status_query(&NodeStatusQuery {
            after: u64::MAX,
            ..query
        })
        .is_err());
    }

    #[test]
    fn entry_layout_matches_the_device_codec() {
        let mut bytes = Vec::new();
        entry(5, true).encode_into(&mut bytes);
        assert_eq!(
            bytes,
            [
                0, 0, 0, 0, 0, 0, 0, 5, 0x3f, 0xb9, 0xb9, 0xb0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 5,
                0, 0, 0x04, 0xd2
            ]
        );
        let decoded = NodeStatusEntry::decode(&bytes).unwrap();
        assert_eq!(decoded, entry(5, true));
        assert_eq!(decoded.rssi_ewma_dbm(), Some(-18000.0 / 256.0));
        // Reserved flag bit, node 0, reachable without next hop.
        for (index, value) in [(8, 0xbf), (7, 0), (23, 0)] {
            let mut bad = bytes.clone();
            bad[index] = value;
            assert!(NodeStatusEntry::decode(&bad).is_err(), "{index}");
        }
        // Direct without reachable.
        let mut bad = bytes.clone();
        bad[8] = FLAG_DIRECT;
        bad[16..24].copy_from_slice(&[0; 8]);
        assert!(NodeStatusEntry::decode(&bad).is_err());
    }

    #[test]
    fn page_round_trip_and_rejections() {
        let page = NodeStatusPage {
            result: 0,
            flags: PAGE_MORE | PAGE_ARMED,
            next_after: 700,
            event_seq: 42,
            entries: vec![entry(5, true), entry(9, false), entry(700, true)],
        };
        let bytes = encode_node_status_page(&page).unwrap();
        assert_eq!(bytes.len(), INNER_HEAD_SIZE + PAGE_FIXED + 3 * ENTRY_SIZE);
        let back = decode_node_status_page(&bytes).unwrap();
        assert_eq!(back, page);
        assert!(back.more() && back.armed() && back.ok());

        let e0 = INNER_HEAD_SIZE + PAGE_FIXED;
        for (index, value) in [
            (6, 0x04),
            (7, 2),
            (15, 0x01),
            (e0 + 8, 0xbf),
            (e0 + 7, 0),
            (e0 + 7, 9),
            (e0 + 23, 0),
            (5, 99),
        ] {
            let mut bad = bytes.clone();
            bad[index] = value;
            assert!(decode_node_status_page(&bad).is_err(), "{index}={value}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_node_status_page(&trailing).is_err());

        let unsupported = NodeStatusPage {
            result: ConfigOpsResult::Unsupported as u16,
            flags: 0,
            next_after: 0,
            event_seq: 0,
            entries: Vec::new(),
        };
        let bytes = encode_node_status_page(&unsupported).unwrap();
        assert!(!decode_node_status_page(&bytes).unwrap().ok());
        assert!(encode_node_status_page(&NodeStatusPage {
            entries: vec![entry(5, true)],
            next_after: 5,
            ..unsupported
        })
        .is_err());
        assert!(encode_node_status_page(&NodeStatusPage {
            entries: vec![entry(9, true), entry(5, true)],
            ..page
        })
        .is_err());
    }

    #[test]
    fn event_round_trip_and_rejections() {
        let event = NodeEvent {
            sequence: 7,
            kind: NodeEventKind::RouteDown,
            status: entry(9, false),
        };
        let bytes = encode_node_event(&event).unwrap();
        assert_eq!(bytes.len(), INNER_HEAD_SIZE + EVENT_PAYLOAD);
        assert_eq!(&bytes[..4], &[1, 0x42, 0, EVENT_PAYLOAD as u8]);
        assert_eq!(decode_node_event(&bytes).unwrap(), event);
        for (index, value) in [(8, 0), (8, 6), (9, 1), (7, 0)] {
            let mut bad = bytes.clone();
            bad[index] = value;
            assert!(decode_node_event(&bad).is_err(), "{index}={value}");
        }
        assert!(encode_node_event(&NodeEvent {
            sequence: 0,
            ..event
        })
        .is_err());
        assert_eq!(node_status_sub(&bytes), Some(SUB_NODE_EVENT));
        assert_eq!(node_status_sub(&[1, 0x31]), None);
        assert_eq!(node_status_sub(&[2, 0x41]), None);
    }
}
