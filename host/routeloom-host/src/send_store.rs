//! Operation table for the send path (Issue #8 / TX-I1, store seam for #9).
//!
//! `OperationStore` is the seam CAP-I1 implements durably (SQLite): epochs,
//! idempotency records and lookups behind one interface so api1.rs never
//! touches storage directly. `MemoryOperationStore` is the TX-I1
//! implementation — bounded RAM only, no persistence, no expiry, no epoch
//! rotation. Everything stays HOST_QUEUED: dispatch to USB is CAP-I2/TX-I2.
//!
//! Identity is `(uid, network, admission_epoch, caller_key)`; the first
//! submit assigns `lineage:seq` and replays return the same id. Same
//! identity with different canonical bytes is a CONFLICT and the stored
//! record is never overwritten. Bounds: 4096 records (contracts.json
//! `capacity.host_records`) and 64 epoch scopes; both reject with
//! NO_CAPACITY. Retention/retire/floor are CAP-I1 and intentionally absent.

use crate::canonical::SendRequest;
use std::collections::HashMap;

// contracts.json `capacity.host_records`; scope cap is a TX-I1 RAM bound.
pub const RECORD_CAP: usize = 4096;
pub const SCOPE_CAP: usize = 64;

/// Scope whose admission epoch is tracked: one epoch per principal×network.
pub type EpochScope = (u32, u64);

/// Full identity of one caller submission (03-send-api.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpIdentity {
    pub uid: u32,
    pub network: u64,
    pub epoch: u64,
    pub key: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct StoredOperation {
    pub seq: u64,
    /// Owning principal — recorded for the CAP-I1 audit/dispatcher handoff;
    /// TX-I1 queries authorize on the network grant, not this field.
    #[allow(dead_code)]
    pub uid: u32,
    pub network: u64,
    pub epoch: u64,
    pub key: [u8; 16],
    pub dest_kind: u8,
    pub dest: u64,
    pub delivery: u8,
    pub priority: u8,
    pub ttl_ms: u32,
    pub storage: u8,
    pub hop_limit: u8,
    /// Payload bytes are retained for the CAP-I1/TX-I2 dispatcher handoff;
    /// nothing in TX-I1 transmits them.
    pub payload: Vec<u8>,
    pub canonical: Vec<u8>,
    pub hash: [u8; 32],
    pub accepted_ms: u64,
}

pub enum SubmitOutcome {
    Accepted {
        seq: u64,
    },
    Replay {
        seq: u64,
    },
    Conflict {
        existing_seq: u64,
    },
    /// Epoch well-formed but never opened for this scope in this store.
    UnknownEpoch,
    NoCapacity,
}

pub trait OperationStore {
    fn lineage(&self) -> [u8; 16];
    /// Bind the scope's admission epoch, opening epoch 1 on first use.
    /// `Ok((epoch, created))`; `Err(())` when no scope slot remains.
    fn open_epoch(&mut self, scope: EpochScope) -> Result<(u64, bool), ()>;
    fn submit(&mut self, uid: u32, req: &SendRequest, now_ms: u64) -> SubmitOutcome;
    fn get_by_seq(&self, seq: u64) -> Option<StoredOperation>;
    fn get_by_key(&self, identity: &OpIdentity) -> Option<StoredOperation>;
}

pub struct MemoryOperationStore {
    lineage: [u8; 16],
    next_seq: u64,
    epochs: HashMap<EpochScope, u64>,
    by_identity: HashMap<OpIdentity, u64>,
    by_seq: HashMap<u64, StoredOperation>,
}

impl MemoryOperationStore {
    pub fn new(lineage: [u8; 16]) -> Self {
        Self {
            lineage,
            next_seq: 1,
            epochs: HashMap::new(),
            by_identity: HashMap::new(),
            by_seq: HashMap::new(),
        }
    }

    /// Zero lineage for unit tests; the daemon mints a fresh one per start.
    pub fn test_store() -> Self {
        Self::new([0; 16])
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_seq.len()
    }

    #[cfg(test)]
    pub fn scope_count(&self) -> usize {
        self.epochs.len()
    }
}

impl Default for MemoryOperationStore {
    fn default() -> Self {
        Self::test_store()
    }
}

impl OperationStore for MemoryOperationStore {
    fn lineage(&self) -> [u8; 16] {
        self.lineage
    }

    fn open_epoch(&mut self, scope: EpochScope) -> Result<(u64, bool), ()> {
        if let Some(epoch) = self.epochs.get(&scope) {
            return Ok((*epoch, false));
        }
        if self.epochs.len() >= SCOPE_CAP {
            return Err(());
        }
        self.epochs.insert(scope, 1);
        Ok((1, true))
    }

    fn submit(&mut self, uid: u32, req: &SendRequest, now_ms: u64) -> SubmitOutcome {
        let identity = OpIdentity {
            uid,
            network: req.network,
            epoch: req.epoch,
            key: req.key,
        };
        // Known identity first: same bytes replay, different bytes conflict —
        // ahead of epoch/capacity checks so a lost response stays recoverable.
        if let Some(seq) = self.by_identity.get(&identity) {
            let stored = self.by_seq.get(seq).expect("identity without record");
            return if stored.canonical == req.canonical {
                SubmitOutcome::Replay { seq: *seq }
            } else {
                SubmitOutcome::Conflict { existing_seq: *seq }
            };
        }
        if self.epochs.get(&(uid, req.network)) != Some(&req.epoch) {
            return SubmitOutcome::UnknownEpoch;
        }
        if self.by_seq.len() >= RECORD_CAP {
            return SubmitOutcome::NoCapacity;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1).max(1);
        self.by_identity.insert(identity, seq);
        self.by_seq.insert(
            seq,
            StoredOperation {
                seq,
                uid,
                network: req.network,
                epoch: req.epoch,
                key: req.key,
                dest_kind: req.dest_kind,
                dest: req.dest,
                delivery: req.delivery,
                priority: req.priority,
                ttl_ms: req.ttl_ms,
                storage: req.storage,
                hop_limit: req.hop_limit,
                payload: req.payload.clone(),
                canonical: req.canonical.clone(),
                hash: req.hash,
                accepted_ms: now_ms,
            },
        );
        SubmitOutcome::Accepted { seq }
    }

    fn get_by_seq(&self, seq: u64) -> Option<StoredOperation> {
        self.by_seq.get(&seq).cloned()
    }

    fn get_by_key(&self, identity: &OpIdentity) -> Option<StoredOperation> {
        self.by_identity
            .get(identity)
            .and_then(|seq| self.by_seq.get(seq))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{parse_submit, STORAGE_RAM};

    fn request(key: &str, epoch: u64, payload_hex: &str, payload_len: u64) -> SendRequest {
        let json = format!(
            "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch:016x}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"{payload_hex}\",\"payload_len\":{payload_len},\"options\":{{\"storage\":\"RAM_ONLY\"}}}}"
        );
        let mut req = parse_submit(&routeloom_json::parse(&json).unwrap()).unwrap();
        assert_eq!(req.storage, STORAGE_RAM);
        req.epoch = epoch;
        req
    }

    fn submit(store: &mut MemoryOperationStore, req: &SendRequest) -> u64 {
        match store.submit(501, req, 1000) {
            SubmitOutcome::Accepted { seq } => seq,
            _ => panic!("expected accept"),
        }
    }

    #[test]
    fn open_epoch_binds_one_per_scope() {
        let mut store = MemoryOperationStore::test_store();
        assert_eq!(store.open_epoch((501, 1)), Ok((1, true)));
        assert_eq!(store.open_epoch((501, 1)), Ok((1, false)));
        assert_eq!(store.open_epoch((501, 2)), Ok((1, true)));
        assert_eq!(store.open_epoch((7, 1)), Ok((1, true)));
        assert_eq!(store.scope_count(), 3);
    }

    #[test]
    fn submit_assigns_stable_ids_and_replays() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1)).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 1, "00ff", 2);
        let seq = submit(&mut store, &req);
        assert_eq!(seq, 1);
        // Same key+payload replays the same id without a new record.
        match store.submit(501, &req, 2000) {
            SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
            _ => panic!("expected replay"),
        }
        assert_eq!(store.len(), 1);
        // Same key under another principal is a separate identity.
        store.open_epoch((7, 1)).unwrap();
        match store.submit(7, &req, 2000) {
            SubmitOutcome::Accepted { seq } => assert_eq!(seq, 2),
            _ => panic!("expected separate accept"),
        }
        // Lookups resolve both ways.
        let by_seq = store.get_by_seq(1).unwrap();
        assert_eq!(by_seq.payload, vec![0x00, 0xff]);
        assert_eq!(by_seq.accepted_ms, 1000); // replay does not re-stamp
        let identity = OpIdentity {
            uid: 501,
            network: 1,
            epoch: 1,
            key: req.key,
        };
        assert_eq!(store.get_by_key(&identity).unwrap().seq, 1);
        assert!(store.get_by_seq(99).is_none());
    }

    #[test]
    fn same_key_different_payload_conflicts_and_preserves() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1)).unwrap();
        let first = request("00112233445566778899aabbccddeeff", 1, "00", 1);
        submit(&mut store, &first);
        for alt in [
            request("00112233445566778899aabbccddeeff", 1, "01", 1),
            request("00112233445566778899aabbccddeeff", 1, "", 0),
        ] {
            match store.submit(501, &alt, 2000) {
                SubmitOutcome::Conflict { existing_seq } => assert_eq!(existing_seq, 1),
                _ => panic!("expected conflict"),
            }
        }
        assert_eq!(store.len(), 1);
        assert_eq!(store.get_by_seq(1).unwrap().payload, vec![0x00]);
    }

    #[test]
    fn option_changes_conflict_too() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1)).unwrap();
        let json = |ttl: u32| {
            format!(
                "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{{\"storage\":\"RAM_ONLY\",\"ttl_ms\":{ttl}}}}}"
            )
        };
        let a = parse_submit(&routeloom_json::parse(&json(5000)).unwrap()).unwrap();
        let b = parse_submit(&routeloom_json::parse(&json(6000)).unwrap()).unwrap();
        submit(&mut store, &a);
        assert!(matches!(
            store.submit(501, &b, 2000),
            SubmitOutcome::Conflict { .. }
        ));
    }

    #[test]
    fn unknown_epoch_rejects_new_key() {
        let mut store = MemoryOperationStore::test_store();
        // Scope never opened.
        let req = request("00112233445566778899aabbccddeeff", 1, "", 0);
        assert!(matches!(
            store.submit(501, &req, 1000),
            SubmitOutcome::UnknownEpoch
        ));
        // Open epoch is 1; epoch 2 was never issued to this scope.
        store.open_epoch((501, 1)).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 2, "", 0);
        assert!(matches!(
            store.submit(501, &req, 1000),
            SubmitOutcome::UnknownEpoch
        ));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn table_and_scope_caps_reject() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1)).unwrap();
        for i in 0..RECORD_CAP {
            let req = request(&format!("{i:032x}"), 1, "", 0);
            assert!(matches!(
                store.submit(501, &req, 1000),
                SubmitOutcome::Accepted { .. }
            ));
        }
        let extra = request(&format!("{:032x}", RECORD_CAP), 1, "", 0);
        assert!(matches!(
            store.submit(501, &extra, 1000),
            SubmitOutcome::NoCapacity
        ));
        // Replays and conflicts still resolve when full — they add nothing.
        let known = request(&format!("{:032x}", 7), 1, "", 0);
        assert!(matches!(
            store.submit(501, &known, 2000),
            SubmitOutcome::Replay { .. }
        ));
        let mut scopes = MemoryOperationStore::test_store();
        for uid in 0..SCOPE_CAP as u32 {
            assert!(scopes.open_epoch((uid, 1)).is_ok());
        }
        assert!(scopes.open_epoch((9999, 1)).is_err());
    }
}
