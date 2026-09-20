//! Bounded per-network receive log (Issue #7 / RX-I1).
//!
//! A `ReceiveLog` retains the actual payload bytes of verified
//! `DataFromMesh` records so PC applications can poll them back with
//! `messages.read`. This is host RAM observation history — evidence level
//! `HOST_RAM_RETAINED`, `endpoint_kind = "gateway_mirror"` — not a durable
//! store and not a mesh dedup ledger.
//!
//! Budgets are pinned by `docs/design/host-security-readiness/contracts.json`
//! (`receive.*`): per-network 4096 records AND 2MiB at a flat 512B record
//! charge, 300s retention, at most 4 networks, 8MiB global. The first limit
//! reached reclaims the *oldest* records; the reclaimed sequence boundary is
//! kept as a tombstone (`evicted_through`) so a slow reader gets an explicit
//! CURSOR_GAP instead of a silent skip.
//!
//! Cursors are opaque base64url (no padding) tokens decoding to a fixed
//! 41-byte body: version(1) | network(8) | acl_view(8) | epoch(16) |
//! last_scanned_seq(8) — under the 96-byte contract cap. The daemon mints a
//! fresh 128-bit epoch at every start, so a cursor from a previous run fails
//! as CURSOR_EPOCH_CHANGED rather than pointing at recycled sequence space.

use std::collections::{HashMap, VecDeque};

// contracts.json `receive.*`
pub const RETENTION_SECONDS: u64 = 300;
pub const ENTRIES_PER_NETWORK: usize = 4096;
pub const BYTES_PER_NETWORK: usize = 2_097_152;
pub const RECORD_CHARGE_BYTES: usize = 512;
pub const MAX_NETWORKS: usize = 4;
pub const GLOBAL_LOG_BYTES: usize = 8_388_608;
pub const DEDUP_SECONDS: u64 = 60;
pub const PAGE_LIMIT: usize = 32;
pub const CURSOR_MAX_DECODED_BYTES: usize = 96;

/// Wire-v1 payload ceiling: a DataFromMesh inner body is
/// origin(8)+session(4)+sequence(8)+payload, payload ≤ 128B.
pub const NORMAL_PAYLOAD_MAX: usize = 128;

const RETENTION_MS: u64 = RETENTION_SECONDS * 1000;
const DEDUP_MS: u64 = DEDUP_SECONDS * 1000;
/// Hard cap on the dedup index; entries older than the dedup window are
/// purged anyway, so this only bounds worst-case distinct keys per window.
const DEDUP_MAX_KEYS: usize = ENTRIES_PER_NETWORK;

/// One retained receive record. `seq` is the log-local monotone position
/// (per network, per epoch, starting at 1) — *not* the mesh MessageId.
#[derive(Clone, Debug)]
pub struct RxRecord {
    pub seq: u64,
    pub network: u64,
    /// Adapter (gateway) node id observed at ingest; `None` is emitted as
    /// JSON null — never synthesized.
    pub gateway: Option<u64>,
    pub origin: u64,
    pub msg_session: u32,
    pub msg_seq: u64,
    pub payload: Vec<u8>,
    pub stored_ms: u64,
}

/// Fields a verified DataFromMesh body contributes to the log.
pub struct Ingress {
    pub network: u64,
    pub gateway: Option<u64>,
    pub origin: u64,
    pub msg_session: u32,
    pub msg_seq: u64,
    pub payload: Vec<u8>,
}

pub enum IngestOutcome {
    /// New record appended; carries its log sequence.
    Stored {
        /// Assigned log position (asserted by tests; the daemon's ingest
        /// path only distinguishes stored/not-stored).
        #[allow(dead_code)]
        seq: u64,
    },
    /// Same MessageKey + identical payload inside the dedup window: folded
    /// into the existing record (its seq is returned; nothing is rewritten).
    Duplicate {
        /// Seq of the record the duplicate folded into.
        #[allow(dead_code)]
        seq: u64,
    },
    /// Same MessageKey, different payload inside the window: the existing
    /// record is authoritative and is never overwritten. Caller emits a
    /// CONFLICT diagnostic.
    Conflict { existing_seq: u64 },
    /// Ingest arrived for a network beyond MAX_NETWORKS: the record is
    /// dropped and the caller emits a diagnostic.
    RejectedNetworkCap,
    /// Payload exceeds the wire-v1 normal ceiling: dropped, diagnostic.
    RejectedOversize,
}

/// Outcome of a cursor-resolved read.
pub enum ReadOutcome {
    Batch(ReadBatch),
    /// Reader's next position was reclaimed: `lost` is the closed log-seq
    /// range [lost_from, lost_to] that no longer exists.
    Gap {
        lost_from: u64,
        lost_to: u64,
        oldest_seq: u64,
        tail_seq: u64,
    },
    /// Cursor points past the current tail — a fabricated/future position.
    Future,
}

/// A bounded batch copied out from under the log lock; the caller formats
/// and writes it to the socket only after the lock is released.
pub struct ReadBatch {
    pub records: Vec<RxRecord>,
    /// True when retained records remain beyond the last returned seq.
    pub more: bool,
    /// Seq of the first retained record (`tail_seq + 1` when empty).
    pub oldest_seq: u64,
    /// Highest seq ever assigned (`0` before the first record).
    pub tail_seq: u64,
    /// Position the read started from — the resume point for `next_cursor`
    /// when the batch is empty (a caught-up reader stays at its position
    /// instead of rewinding to `oldest_seq - 1`).
    pub after_seq: u64,
    pub entries: usize,
    pub bytes: usize,
}

/// Mesh identity of one message within one network.
type MessageKey = (u64, u32, u64); // (origin, msg_session, msg_seq)

struct DedupEntry {
    seq: u64,
    ms: u64,
}

struct NetworkLog {
    records: VecDeque<RxRecord>,
    /// Highest seq reclaimed from the front (tombstone for CURSOR_GAP).
    evicted_through: u64,
    /// Next seq to assign; tail = next_seq - 1.
    next_seq: u64,
    /// MessageKey -> retained record for the 60s duplicate window.
    dedup: HashMap<MessageKey, DedupEntry>,
    bytes: usize,
}

impl NetworkLog {
    fn new() -> Self {
        Self {
            records: VecDeque::new(),
            evicted_through: 0,
            next_seq: 1,
            dedup: HashMap::new(),
            bytes: 0,
        }
    }

    fn oldest_seq(&self) -> u64 {
        self.records.front().map_or(self.next_seq, |r| r.seq)
    }

    fn tail_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// Drop expired records from the front; records are seq/time ordered.
    fn expire(&mut self, now_ms: u64) {
        while let Some(front) = self.records.front() {
            if now_ms.saturating_sub(front.stored_ms) < RETENTION_MS {
                break;
            }
            let record = self.records.pop_front().expect("front exists");
            self.evicted_through = record.seq;
            self.bytes = self.bytes.saturating_sub(RECORD_CHARGE_BYTES);
            self.dedup.retain(|_, e| e.seq != record.seq);
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(record) = self.records.pop_front() {
            self.evicted_through = record.seq;
            self.bytes = self.bytes.saturating_sub(RECORD_CHARGE_BYTES);
            self.dedup.retain(|_, e| e.seq != record.seq);
        }
    }

    /// Forget dedup entries outside the window; if the index is still full,
    /// drop the oldest entry — a missed dedup only costs a duplicate record,
    /// never a wrong answer (conflicts still check the retained record).
    fn trim_dedup(&mut self, now_ms: u64) {
        self.dedup
            .retain(|_, e| now_ms.saturating_sub(e.ms) < DEDUP_MS);
        while self.dedup.len() >= DEDUP_MAX_KEYS {
            let oldest = self.dedup.iter().min_by_key(|(_, e)| e.ms).map(|(k, _)| *k);
            match oldest {
                Some(key) => {
                    self.dedup.remove(&key);
                }
                None => break,
            }
        }
    }
}

pub struct ReceiveLog {
    /// 128-bit epoch minted at daemon start; restart == new epoch.
    epoch: [u8; 16],
    networks: HashMap<u64, NetworkLog>,
    total_bytes: usize,
}

impl Default for ReceiveLog {
    /// Zero epoch for unit tests; the daemon always uses `ReceiveLog::new`
    /// with a freshly minted epoch.
    fn default() -> Self {
        Self::new([0; 16])
    }
}

impl ReceiveLog {
    pub fn new(epoch: [u8; 16]) -> Self {
        Self {
            epoch,
            networks: HashMap::new(),
            total_bytes: 0,
        }
    }

    pub fn epoch(&self) -> [u8; 16] {
        self.epoch
    }

    /// Feed one verified DataFromMesh body into the log.
    pub fn ingest(&mut self, ingress: Ingress, now_ms: u64) -> IngestOutcome {
        if ingress.payload.len() > NORMAL_PAYLOAD_MAX {
            return IngestOutcome::RejectedOversize;
        }
        self.expire_all(now_ms);
        if !self.networks.contains_key(&ingress.network) && self.networks.len() >= MAX_NETWORKS {
            return IngestOutcome::RejectedNetworkCap;
        }
        let log = self
            .networks
            .entry(ingress.network)
            .or_insert_with(NetworkLog::new);
        let key: MessageKey = (ingress.origin, ingress.msg_session, ingress.msg_seq);
        // 60s dedup window: identical re-observation folds into the existing
        // record; a differing body under the same key is a conflict and the
        // retained record is never overwritten.
        if let Some(entry) = log.dedup.get(&key) {
            if now_ms.saturating_sub(entry.ms) < DEDUP_MS {
                if let Some(record) = log.records.iter().find(|r| r.seq == entry.seq) {
                    return if record.payload == ingress.payload {
                        IngestOutcome::Duplicate { seq: entry.seq }
                    } else {
                        IngestOutcome::Conflict {
                            existing_seq: entry.seq,
                        }
                    };
                }
                // Referenced record was reclaimed: the original payload is
                // unknowable, so treat this as a new observation.
            }
        }
        let seq = log.next_seq;
        log.next_seq = log.next_seq.saturating_add(1);
        log.records.push_back(RxRecord {
            seq,
            network: ingress.network,
            gateway: ingress.gateway,
            origin: ingress.origin,
            msg_session: ingress.msg_session,
            msg_seq: ingress.msg_seq,
            payload: ingress.payload,
            stored_ms: now_ms,
        });
        log.bytes += RECORD_CHARGE_BYTES;
        self.total_bytes += RECORD_CHARGE_BYTES;
        log.dedup.insert(key, DedupEntry { seq, ms: now_ms });
        log.trim_dedup(now_ms);
        // First-hit limits reclaim from the front, keeping evicted_through.
        while log.records.len() > ENTRIES_PER_NETWORK || log.bytes > BYTES_PER_NETWORK {
            log.evict_oldest();
            self.total_bytes = self.total_bytes.saturating_sub(RECORD_CHARGE_BYTES);
        }
        // Global cap: reclaim the globally-oldest record across networks.
        while self.total_bytes > GLOBAL_LOG_BYTES {
            let victim = self
                .networks
                .iter()
                .filter_map(|(n, l)| l.records.front().map(|r| (*n, r.seq, r.stored_ms)))
                .min_by_key(|(_, seq, ms)| (*ms, *seq))
                .map(|(n, ..)| n);
            match victim {
                Some(network) => {
                    if let Some(log) = self.networks.get_mut(&network) {
                        log.evict_oldest();
                    }
                    self.total_bytes = self.total_bytes.saturating_sub(RECORD_CHARGE_BYTES);
                }
                None => break,
            }
        }
        IngestOutcome::Stored { seq }
    }

    fn expire_all(&mut self, now_ms: u64) {
        for log in self.networks.values_mut() {
            let before = log.bytes;
            log.expire(now_ms);
            self.total_bytes = self.total_bytes.saturating_sub(before - log.bytes);
        }
    }

    /// Cursor-resolved read: records with seq > `after_seq`, ≤ `limit`.
    /// `check_position` is false only for an explicit `from=earliest`/
    /// `latest` request. A real cursor (true) parked behind
    /// `evicted_through` — including position 0 — reports Gap instead of
    /// silently skipping reclaimed records; one beyond tail is Future.
    pub fn read(
        &mut self,
        network: u64,
        after_seq: u64,
        limit: usize,
        now_ms: u64,
        check_position: bool,
    ) -> ReadOutcome {
        self.expire_all(now_ms);
        let Some(log) = self.networks.get(&network) else {
            return ReadOutcome::Batch(ReadBatch {
                records: Vec::new(),
                more: false,
                oldest_seq: 1,
                tail_seq: 0,
                after_seq,
                entries: 0,
                bytes: 0,
            });
        };
        let oldest = log.oldest_seq();
        let tail = log.tail_seq();
        if check_position {
            if after_seq > tail {
                return ReadOutcome::Future;
            }
            if after_seq < log.evicted_through {
                return ReadOutcome::Gap {
                    lost_from: after_seq + 1,
                    lost_to: log.evicted_through,
                    oldest_seq: oldest,
                    tail_seq: tail,
                };
            }
        }
        let mut records = Vec::new();
        for record in &log.records {
            if record.seq > after_seq {
                records.push(record.clone());
                if records.len() >= limit {
                    break;
                }
            }
        }
        let last = records.last().map_or(after_seq, |r| r.seq);
        ReadOutcome::Batch(ReadBatch {
            more: last < tail,
            records,
            oldest_seq: oldest,
            tail_seq: tail,
            after_seq,
            entries: log.records.len(),
            bytes: log.bytes,
        })
    }

    /// Snapshot for building oldest/tail cursors without a read.
    pub fn bounds(&mut self, network: u64, now_ms: u64) -> (u64, u64, usize, usize) {
        self.expire_all(now_ms);
        match self.networks.get(&network) {
            Some(log) => (
                log.oldest_seq(),
                log.tail_seq(),
                log.records.len(),
                log.bytes,
            ),
            None => (1, 0, 0, 0),
        }
    }
}

/// Decoded read cursor — fixed 41-byte body, emitted base64url no-pad.
/// A cursor is a *position*, not a permission: the caller re-checks the
/// OS principal's ACL on every request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub network: u64,
    pub acl_view: u64,
    pub epoch: [u8; 16],
    pub last_scanned: u64,
}

pub const CURSOR_VERSION: u8 = 1;
const CURSOR_BYTES: usize = 1 + 8 + 8 + 16 + 8; // 41 ≤ CURSOR_MAX_DECODED_BYTES

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64URL[(n >> 18) as usize & 0x3f] as char);
        out.push(B64URL[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 0x3f] as char);
        }
    }
    out
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None, // includes '=' padding — not accepted
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            if out.len() > CURSOR_MAX_DECODED_BYTES {
                return None;
            }
        }
    }
    // A valid no-pad encoding of N bytes never leaves a partial byte whose
    // leftover bits are nonzero-or-shorter than a full sextet boundary…
    // accept only clean lengths: total bits mod 8 leaves 0, 2, or 4 spare
    // bits which must be zero to be canonical.
    match bits {
        0 => {}
        2 | 4 if acc & ((1 << bits) - 1) == 0 => {}
        _ => return None,
    }
    Some(out)
}

impl Cursor {
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(CURSOR_BYTES);
        raw.push(CURSOR_VERSION);
        raw.extend_from_slice(&self.network.to_be_bytes());
        raw.extend_from_slice(&self.acl_view.to_be_bytes());
        raw.extend_from_slice(&self.epoch);
        raw.extend_from_slice(&self.last_scanned.to_be_bytes());
        b64url_encode(&raw)
    }

    /// Malformed encoding/wrong size/wrong version — all INVALID_CURSOR.
    pub fn decode(token: &str) -> Option<Cursor> {
        let raw = b64url_decode(token)?;
        if raw.len() != CURSOR_BYTES || raw[0] != CURSOR_VERSION {
            return None;
        }
        Some(Cursor {
            network: u64::from_be_bytes(raw[1..9].try_into().expect("8")),
            acl_view: u64::from_be_bytes(raw[9..17].try_into().expect("8")),
            epoch: raw[17..33].try_into().expect("16"),
            last_scanned: u64::from_be_bytes(raw[33..41].try_into().expect("8")),
        })
    }
}

/// Lowercase hex encoding for payload bytes (contract: `binary_encoding =
/// "lowercase_hex"`, length always 2×payload_len; empty payload = "").
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ingress(origin: u64, msg_seq: u64, payload: &[u8]) -> Ingress {
        Ingress {
            network: 1,
            gateway: Some(2),
            origin,
            msg_session: 5,
            msg_seq,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn ingest_and_read_roundtrip() {
        let mut log = ReceiveLog::new([7; 16]);
        for (i, payload) in [b"".as_slice(), b"x", &[0x00, 0xff, 0x80]]
            .iter()
            .enumerate()
        {
            match log.ingest(ingress(3, i as u64, payload), 1000) {
                IngestOutcome::Stored { seq } => assert_eq!(seq, i as u64 + 1),
                _ => panic!("expected store"),
            }
        }
        let ReadOutcome::Batch(batch) = log.read(1, 0, 32, 1001, true) else {
            panic!("expected batch")
        };
        assert_eq!(batch.records.len(), 3);
        assert_eq!(batch.records[0].payload, b"");
        assert_eq!(batch.records[1].payload, b"x");
        assert_eq!(batch.records[2].payload, &[0x00, 0xff, 0x80]);
        assert!(!batch.more);
        assert_eq!(batch.oldest_seq, 1);
        assert_eq!(batch.tail_seq, 3);
        assert_eq!(batch.entries, 3);
        assert_eq!(batch.bytes, 3 * RECORD_CHARGE_BYTES);
    }

    #[test]
    fn dedup_folds_identical_and_conflicts_different() {
        let mut log = ReceiveLog::new([7; 16]);
        log.ingest(ingress(3, 9, b"same"), 1000);
        match log.ingest(ingress(3, 9, b"same"), 30_000) {
            IngestOutcome::Duplicate { seq } => assert_eq!(seq, 1),
            _ => panic!("expected dedup"),
        }
        match log.ingest(ingress(3, 9, b"diff"), 40_000) {
            IngestOutcome::Conflict { existing_seq } => assert_eq!(existing_seq, 1),
            _ => panic!("expected conflict"),
        }
        // Original payload is untouched.
        let ReadOutcome::Batch(batch) = log.read(1, 0, 32, 40_001, true) else {
            panic!("expected batch")
        };
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].payload, b"same");
        // Outside the 60s window the same key is a fresh observation.
        match log.ingest(ingress(3, 9, b"same"), 1000 + DEDUP_MS + 1) {
            IngestOutcome::Stored { seq } => assert_eq!(seq, 2),
            _ => panic!("expected new record after window"),
        }
    }

    #[test]
    fn count_cap_evicts_oldest_and_gaps_slow_reader() {
        let mut log = ReceiveLog::new([7; 16]);
        for i in 0..ENTRIES_PER_NETWORK + 3 {
            log.ingest(ingress(3, i as u64, b"p"), 1000);
        }
        // from=earliest skips position checks and sees the post-eviction
        // state directly.
        let ReadOutcome::Batch(batch) = log.read(1, 0, 1, 1000, false) else {
            panic!("expected batch")
        };
        assert_eq!(batch.entries, ENTRIES_PER_NETWORK);
        assert_eq!(batch.oldest_seq, 4);
        // Cursor at seq 1 is now behind the tombstone → explicit GAP.
        match log.read(1, 1, 32, 1000, true) {
            ReadOutcome::Gap {
                lost_from,
                lost_to,
                oldest_seq,
                tail_seq,
            } => {
                assert_eq!(lost_from, 2);
                assert_eq!(lost_to, 3);
                assert_eq!(oldest_seq, 4);
                assert_eq!(tail_seq, (ENTRIES_PER_NETWORK + 3) as u64);
            }
            _ => panic!("expected gap"),
        }
        // Position at the tombstone boundary resumes cleanly.
        let ReadOutcome::Batch(batch) = log.read(1, 3, 2, 1000, true) else {
            panic!("expected batch")
        };
        assert_eq!(batch.records[0].seq, 4);
    }

    #[test]
    fn retention_expiry_reclaims_and_reports() {
        let mut log = ReceiveLog::new([7; 16]);
        log.ingest(ingress(3, 1, b"old"), 0);
        log.ingest(ingress(3, 2, b"new"), RETENTION_MS + 1);
        // from=earliest observes only what is still retained.
        let ReadOutcome::Batch(batch) = log.read(1, 0, 32, RETENTION_MS + 1, false) else {
            panic!("expected batch")
        };
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].payload, b"new");
        assert_eq!(batch.oldest_seq, 2);
        // A reader parked at seq 0 sees the expiry as a GAP.
        match log.read(1, 0, 32, RETENTION_MS + 1, true) {
            ReadOutcome::Gap { lost_to, .. } => assert_eq!(lost_to, 1),
            _ => panic!("expected gap"),
        }
    }

    #[test]
    fn network_and_oversize_and_future_rejects() {
        let mut log = ReceiveLog::new([7; 16]);
        for net in 1..=MAX_NETWORKS as u64 {
            let mut ing = ingress(3, 1, b"p");
            ing.network = net;
            assert!(matches!(
                log.ingest(ing, 1000),
                IngestOutcome::Stored { .. }
            ));
        }
        let mut extra = ingress(3, 2, b"p");
        extra.network = 99;
        assert!(matches!(
            log.ingest(extra, 1000),
            IngestOutcome::RejectedNetworkCap
        ));
        let mut big = ingress(3, 3, &[0; NORMAL_PAYLOAD_MAX + 1]);
        big.network = 1;
        assert!(matches!(
            log.ingest(big, 1000),
            IngestOutcome::RejectedOversize
        ));
        // Cursor beyond tail is INVALID_CURSOR territory (mapped by api1).
        assert!(matches!(
            log.read(1, 999, 32, 1000, true),
            ReadOutcome::Future
        ));
    }

    #[test]
    fn cursor_roundtrip_and_rejects() {
        let cursor = Cursor {
            network: 0xdead_beef,
            acl_view: 1,
            epoch: [0xab; 16],
            last_scanned: 41,
        };
        let token = cursor.encode();
        assert!(!token.contains('='));
        assert!(token.len() <= CURSOR_MAX_DECODED_BYTES * 4 / 3 + 1);
        assert_eq!(Cursor::decode(&token), Some(cursor));
        // Malformed tokens.
        assert_eq!(Cursor::decode(""), None);
        assert_eq!(Cursor::decode("!!!"), None);
        assert_eq!(Cursor::decode("AAAA"), None);
        let mut padded = token.clone();
        padded.push('=');
        assert_eq!(Cursor::decode(&padded), None);
        // Oversize decoded body.
        let huge = b64url_encode(&[0u8; CURSOR_MAX_DECODED_BYTES + 1]);
        assert_eq!(Cursor::decode(&huge), None);
        // Wrong version.
        let mut raw = Vec::new();
        raw.push(2u8);
        raw.extend_from_slice(&0xdead_beef_u64.to_be_bytes());
        raw.extend_from_slice(&1_u64.to_be_bytes());
        raw.extend_from_slice(&[0xab; 16]);
        raw.extend_from_slice(&41_u64.to_be_bytes());
        assert_eq!(Cursor::decode(&b64url_encode(&raw)), None);
    }

    #[test]
    fn hex_lower_is_fixed_width_lowercase() {
        assert_eq!(hex_lower(&[]), "");
        assert_eq!(hex_lower(&[0x00, 0xff, 0x80]), "00ff80");
    }
}
