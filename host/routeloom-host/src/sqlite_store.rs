//! Durable operation store (CAP-I1): the SQLite provider behind the
//! `OperationStore` contract.
//!
//! One database file holds lineage, admission epochs with their retire
//! floor, and every HOST_DURABLE record; RAM_ONLY records live in a memory
//! overlay in front of the same epochs, quotas and sequence space, so the
//! daemon never writes a payload to disk the caller asked to keep in RAM.
//! Each admission (identity check, epoch validity, quota reservation,
//! record insert, sequence bump) commits in a single transaction — only
//! after that commit does the API answer LOCAL_ACCEPTED. WAL mode with
//! FULL synchronous keeps commits power-loss durable where the OS honors
//! flushes; where it does not, the deployment is outside the durable
//! qualification and must say so.
//!
//! Crash rules, all enforced here: a corrupt or unknown-schema file refuses
//! to open (never resurrected as an empty store under an old lineage);
//! reopening replays no dispatch, marks DISPATCH_PREPARED records
//! INDETERMINATE (their USB write may or may not have happened), and leaves
//! every other state untouched — HOST_QUEUED was never transmitted, and
//! INDETERMINATE is never auto-reissued. Retire advances the persisted
//! floor and deletes records atomically over the contiguous retired prefix.

use crate::canonical::SendRequest;
use crate::send_store::{
    mint_id128, CapacityStatus, DispatchState, EpochScope, OpIdentity, OpenEpochError,
    OperationStore, StoredOperation, SubmitOutcome, ACTIVE_CAP, ACTIVE_PER_PRINCIPAL_CAP,
    EPOCH_WINDOW_MS, MAX_UNRETIRED_EPOCHS, RECORD_CAP, RECORD_RESERVATION_BYTES, RETENTION_MS,
    STORE_BYTES_CAP,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 1;

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scope_epoch(
    uid INTEGER NOT NULL, network INTEGER NOT NULL,
    floor BLOB NOT NULL, next_epoch BLOB NOT NULL,
    open_epoch BLOB, open_ms INTEGER,
    PRIMARY KEY(uid, network));
CREATE TABLE IF NOT EXISTS closed_epoch(
    uid INTEGER NOT NULL, network INTEGER NOT NULL, epoch BLOB NOT NULL,
    PRIMARY KEY(uid, network, epoch));
CREATE TABLE IF NOT EXISTS operations(
    seq INTEGER PRIMARY KEY,
    uid INTEGER NOT NULL, network INTEGER NOT NULL,
    epoch BLOB NOT NULL, key BLOB NOT NULL,
    dest_kind INTEGER NOT NULL, dest BLOB NOT NULL,
    delivery INTEGER NOT NULL, priority INTEGER NOT NULL,
    ttl_ms INTEGER NOT NULL, storage INTEGER NOT NULL, hop_limit INTEGER NOT NULL,
    payload BLOB NOT NULL, canonical BLOB NOT NULL, hash BLOB NOT NULL,
    accepted_ms INTEGER NOT NULL,
    dispatch_state TEXT NOT NULL DEFAULT 'HOST_QUEUED',
    terminal_ms INTEGER,
    UNIQUE(uid, network, epoch, key));
CREATE INDEX IF NOT EXISTS idx_operations_scope_epoch
    ON operations(uid, network, epoch);
";

const TERMINAL_SQL: &str =
    "'END_SDK_RECEIVED','EXPIRED_BEFORE_DISPATCH','CANCELLED_BEFORE_DISPATCH','REJECTED_NOT_ACCEPTED'";
const ACTIVE_SQL: &str = "'DISPATCH_PREPARED','GATEWAY_ACCEPTED'";

/// Why the durable store refused to open. The daemon treats every variant
/// as fatal: serving API on a suspect store would risk re-executing old
/// keys or minting a second lineage over them (STORE_RECOVERY_REQUIRED).
#[derive(Debug)]
pub struct OpenError {
    pub message: String,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OpenError {}

impl From<rusqlite::Error> for OpenError {
    fn from(error: rusqlite::Error) -> Self {
        Self {
            message: format!("STORE_RECOVERY_REQUIRED: operation store sqlite error: {error}"),
        }
    }
}

fn ms_to_db(ms: u64) -> i64 {
    ms.min(i64::MAX as u64) as i64
}

fn db_to_ms(value: i64) -> Option<u64> {
    u64::try_from(value).ok()
}

fn u64_blob(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn blob_u64(raw: Vec<u8>) -> Option<u64> {
    let bytes: [u8; 8] = raw.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Footprint of the live store: main file plus WAL sidecars. None when the
/// main file cannot be measured — the daemon then cannot vouch for
/// durability and must stop admitting rather than guess.
fn store_file_bytes(path: &Path) -> Option<u64> {
    let mut total = std::fs::metadata(path).ok()?.len();
    for suffix in ["-wal", "-shm"] {
        let sidecar = format!("{}{suffix}", path.display());
        total += std::fs::metadata(sidecar).map(|m| m.len()).unwrap_or(0);
    }
    Some(total)
}

struct ScopeRow {
    floor: u64,
    next_epoch: u64,
    open: Option<(u64, u64)>,
}

type ScopeRowParts = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<i64>);

fn read_scope(
    tx: &Transaction<'_>,
    scope: EpochScope,
) -> Result<Option<ScopeRow>, rusqlite::Error> {
    let (uid, network) = scope;
    let row: Option<ScopeRowParts> = tx
        .query_row(
            "SELECT floor, next_epoch, open_epoch, open_ms FROM scope_epoch WHERE uid=?1 AND network=?2",
            params![uid, network as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(floor, next, open, open_ms)| {
        let open = open.and_then(blob_u64).zip(open_ms.and_then(db_to_ms));
        let field = |name: &'static str| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, name.into())
        };
        Ok(ScopeRow {
            floor: blob_u64(floor).ok_or_else(|| field("floor"))?,
            next_epoch: blob_u64(next).ok_or_else(|| field("next_epoch"))?,
            open,
        })
    })
    .transpose()
}

fn open_epoch_of(
    tx: &Transaction<'_>,
    scope: EpochScope,
) -> Result<Option<(u64, u64)>, rusqlite::Error> {
    Ok(read_scope(tx, scope)?.and_then(|row| row.open))
}

fn closed_contains(
    tx: &Transaction<'_>,
    scope: EpochScope,
    epoch: u64,
) -> Result<bool, rusqlite::Error> {
    let (uid, network) = scope;
    Ok(tx
        .query_row(
            "SELECT 1 FROM closed_epoch WHERE uid=?1 AND network=?2 AND epoch=?3",
            params![uid, network as i64, u64_blob(epoch)],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn unretired_count(tx: &Transaction<'_>, scope: EpochScope) -> Result<usize, rusqlite::Error> {
    let (uid, network) = scope;
    let closed: i64 = tx.query_row(
        "SELECT COUNT(*) FROM closed_epoch WHERE uid=?1 AND network=?2",
        params![uid, network as i64],
        |row| row.get(0),
    )?;
    let open = usize::from(open_epoch_of(tx, scope)?.is_some());
    Ok(closed as usize + open)
}

fn read_operation_row(row: &rusqlite::Row<'_>) -> Result<StoredOperation, rusqlite::Error> {
    let corrupt = |field: &'static str| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, field.into())
    };
    let epoch = blob_u64(row.get::<_, Vec<u8>>(3)?).ok_or_else(|| corrupt("epoch"))?;
    let key: Vec<u8> = row.get(4)?;
    let key: [u8; 16] = key.try_into().map_err(|_| corrupt("key"))?;
    let dest = blob_u64(row.get::<_, Vec<u8>>(6)?).ok_or_else(|| corrupt("dest"))?;
    let hash: Vec<u8> = row.get(14)?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| corrupt("hash"))?;
    let state_text: String = row.get(16)?;
    let terminal_raw: Option<i64> = row.get(17)?;
    let terminal_ms = match terminal_raw {
        None => None,
        Some(raw) => Some(db_to_ms(raw).ok_or_else(|| corrupt("terminal_ms"))?),
    };
    Ok(StoredOperation {
        seq: row.get::<_, i64>(0)? as u64,
        uid: row.get::<_, i64>(1)? as u32,
        network: row.get::<_, i64>(2)? as u64,
        epoch,
        key,
        dest_kind: row.get::<_, i64>(5)? as u8,
        dest,
        delivery: row.get::<_, i64>(7)? as u8,
        priority: row.get::<_, i64>(8)? as u8,
        ttl_ms: row.get::<_, i64>(9)? as u32,
        storage: row.get::<_, i64>(10)? as u8,
        hop_limit: row.get::<_, i64>(11)? as u8,
        payload: row.get(12)?,
        canonical: row.get(13)?,
        hash,
        accepted_ms: db_to_ms(row.get::<_, i64>(15)?).ok_or_else(|| corrupt("accepted_ms"))?,
        dispatch_state: DispatchState::parse(&state_text)
            .ok_or_else(|| corrupt("dispatch_state"))?,
        terminal_ms,
    })
}

const OPERATION_COLUMNS: &str = "seq, uid, network, epoch, key, dest_kind, dest, delivery, priority, ttl_ms, storage, hop_limit, payload, canonical, hash, accepted_ms, dispatch_state, terminal_ms";

/// RAM-overlay mutations staged inside a transaction and applied only
/// after its commit succeeds — the overlay must never diverge from what
/// the store actually committed: a staged insert surviving a rolled-back
/// `next_seq` could shadow a different durable record with the same seq,
/// and a staged removal could drop an admitted record whose epoch was
/// never retired on disk.
#[derive(Default)]
struct RamDelta {
    /// Record admitted by this transaction (RAM_ONLY).
    admitted: Option<(OpIdentity, StoredOperation)>,
    /// Identities the retire pass dropped inside this transaction.
    retired: Vec<OpIdentity>,
}

pub struct SqliteOperationStore {
    path: PathBuf,
    lineage: [u8; 16],
    conn: Connection,
    ram_by_identity: HashMap<OpIdentity, StoredOperation>,
    ram_by_seq: HashMap<u64, OpIdentity>,
}

impl std::fmt::Debug for SqliteOperationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteOperationStore")
            .field("path", &self.path)
            .field("lineage", &self.lineage)
            .field("ram_records", &self.ram_by_identity.len())
            .finish_non_exhaustive()
    }
}

impl SqliteOperationStore {
    /// Open (or create) the durable store at `path`. An existing file must
    /// be a valid store: corruption, an unknown schema, or a failed
    /// integrity check refuses to open instead of starting empty.
    pub fn open(path: &Path) -> Result<Self, OpenError> {
        let fresh = !path.exists();
        if fresh {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| OpenError {
                    message: format!(
                        "STORE_RECOVERY_REQUIRED: cannot create store directory {}: {e}",
                        parent.display()
                    ),
                })?;
            }
        }
        let conn = Connection::open(path).map_err(|e| OpenError {
            message: format!(
                "STORE_RECOVERY_REQUIRED: cannot open operation store {}: {e}",
                path.display()
            ),
        })?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        // WAL where the filesystem allows it, rollback journal otherwise —
        // either is durable with FULL synchronous.
        let _journal: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        if fresh {
            conn.execute_batch(SCHEMA_SQL)?;
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION.to_be_bytes().to_vec()],
            )?;
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('lineage', ?1)",
                params![mint_id128().to_vec()],
            )?;
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('next_seq', ?1)",
                params![u64_blob(1)],
            )?;
        }
        let version: Vec<u8> = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: {} is not a RouteLoom operation store",
                    path.display()
                ),
            })?;
        if version.as_slice() != SCHEMA_VERSION.to_be_bytes() {
            return Err(OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: {} has an unknown store schema; refusing to erase or migrate it",
                    path.display()
                ),
            });
        }
        let check: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if check != "ok" {
            return Err(OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: {} failed integrity check: {check}",
                    path.display()
                ),
            });
        }
        let lineage: Vec<u8> =
            conn.query_row("SELECT value FROM meta WHERE key='lineage'", [], |row| {
                row.get(0)
            })?;
        let lineage: [u8; 16] = lineage.try_into().map_err(|_| OpenError {
            message: format!(
                "STORE_RECOVERY_REQUIRED: {} has a corrupt store lineage",
                path.display()
            ),
        })?;
        // Crash recovery: DISPATCH_PREPARED records may or may not have
        // reached USB — surface them as indeterminate, never as success,
        // and never re-dispatch them. All other states reload untouched.
        let recovered = conn.execute(
            "UPDATE operations SET dispatch_state='INDETERMINATE' WHERE dispatch_state='DISPATCH_PREPARED'",
            [],
        )?;
        if recovered > 0 {
            eprintln!("opstore: {recovered} prepared operation(s) recovered as INDETERMINATE");
        }
        Ok(Self {
            path: path.to_path_buf(),
            lineage,
            conn,
            ram_by_identity: HashMap::new(),
            ram_by_seq: HashMap::new(),
        })
    }

    fn fault(error: rusqlite::Error) -> SubmitOutcome {
        eprintln!("opstore fault: {error}");
        SubmitOutcome::StoreFault
    }

    fn next_seq_tx(tx: &Transaction<'_>) -> Result<u64, rusqlite::Error> {
        let raw: Vec<u8> =
            tx.query_row("SELECT value FROM meta WHERE key='next_seq'", [], |row| {
                row.get(0)
            })?;
        blob_u64(raw).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                "next_seq".into(),
            )
        })
    }

    /// Same retire rule as the memory provider, applied to durable rows
    /// and the RAM overlay together: floor, closed-set and records move
    /// in the caller's transaction, so a crash leaves either everything
    /// or nothing — never records deleted ahead of the floor. Overlay
    /// removals are only staged in `delta`; the caller applies them
    /// after the commit succeeds.
    fn retire_tx(
        ram_by_identity: &HashMap<OpIdentity, StoredOperation>,
        delta: &mut RamDelta,
        tx: &Transaction<'_>,
        scope: EpochScope,
        now_ms: u64,
    ) -> Result<(), rusqlite::Error> {
        let (uid, network) = scope;
        let Some(row) = read_scope(tx, scope)? else {
            return Ok(());
        };
        let mut floor = row.floor;
        loop {
            let candidate = floor.saturating_add(1);
            if open_epoch_of(tx, scope)?.is_some_and(|(open, _)| open == candidate)
                || !closed_contains(tx, scope, candidate)?
            {
                break;
            }
            let mut eligible = true;
            {
                let mut stmt = tx.prepare(
                    "SELECT dispatch_state, terminal_ms FROM operations WHERE uid=?1 AND network=?2 AND epoch=?3",
                )?;
                let rows = stmt
                    .query_map(params![uid, network as i64, u64_blob(candidate)], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?))
                    })?;
                for row in rows {
                    let (state_text, terminal_raw) = row?;
                    let terminal = terminal_raw.and_then(db_to_ms);
                    let lapsed = terminal.is_some_and(|t| t.saturating_add(RETENTION_MS) <= now_ms);
                    if !DispatchState::parse(&state_text).is_some_and(|s| s.is_terminal())
                        || !lapsed
                    {
                        eligible = false;
                        break;
                    }
                }
            }
            if eligible {
                eligible = ram_by_identity
                    .values()
                    .filter(|op| op.uid == uid && op.network == network && op.epoch == candidate)
                    .all(|op| {
                        op.dispatch_state.is_terminal()
                            && op
                                .terminal_ms
                                .is_some_and(|t| t.saturating_add(RETENTION_MS) <= now_ms)
                    });
            }
            if !eligible {
                break;
            }
            floor = candidate;
            tx.execute(
                "UPDATE scope_epoch SET floor=?3 WHERE uid=?1 AND network=?2",
                params![uid, network as i64, u64_blob(floor)],
            )?;
            tx.execute(
                "DELETE FROM closed_epoch WHERE uid=?1 AND network=?2 AND epoch=?3",
                params![uid, network as i64, u64_blob(candidate)],
            )?;
            tx.execute(
                "DELETE FROM operations WHERE uid=?1 AND network=?2 AND epoch=?3",
                params![uid, network as i64, u64_blob(candidate)],
            )?;
            delta.retired.extend(
                ram_by_identity
                    .keys()
                    .filter(|id| id.uid == uid && id.network == network && id.epoch == candidate)
                    .copied(),
            );
        }
        Ok(())
    }

    /// Apply the staged overlay mutations once the transaction that
    /// produced them has committed.
    fn apply_ram_delta(
        ram_by_identity: &mut HashMap<OpIdentity, StoredOperation>,
        ram_by_seq: &mut HashMap<u64, OpIdentity>,
        delta: RamDelta,
    ) {
        for identity in delta.retired {
            if let Some(op) = ram_by_identity.remove(&identity) {
                ram_by_seq.remove(&op.seq);
            }
        }
        if let Some((identity, op)) = delta.admitted {
            ram_by_seq.insert(op.seq, identity);
            ram_by_identity.insert(identity, op);
        }
    }

    fn submit_tx(
        ram_by_identity: &HashMap<OpIdentity, StoredOperation>,
        delta: &mut RamDelta,
        tx: &Transaction<'_>,
        uid: u32,
        req: &SendRequest,
        now_ms: u64,
    ) -> Result<SubmitOutcome, rusqlite::Error> {
        let identity = OpIdentity {
            uid,
            network: req.network,
            epoch: req.epoch,
            key: req.key,
        };
        if let Some(stored) = ram_by_identity.get(&identity) {
            return Ok(if stored.canonical == req.canonical {
                SubmitOutcome::Replay { seq: stored.seq }
            } else {
                SubmitOutcome::Conflict {
                    existing_seq: stored.seq,
                }
            });
        }
        let durable_hit: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT seq, canonical FROM operations WHERE uid=?1 AND network=?2 AND epoch=?3 AND key=?4",
                params![
                    uid,
                    req.network as i64,
                    u64_blob(req.epoch),
                    req.key.to_vec()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((seq, canonical)) = durable_hit {
            return Ok(if canonical == req.canonical {
                SubmitOutcome::Replay { seq: seq as u64 }
            } else {
                SubmitOutcome::Conflict {
                    existing_seq: seq as u64,
                }
            });
        }
        let scope = (uid, req.network);
        Self::retire_tx(ram_by_identity, delta, tx, scope, now_ms)?;
        match read_scope(tx, scope)? {
            Some(row) if row.open.is_some_and(|(open, _)| open == req.epoch) => {
                // Same rule as the memory provider: an unrotated epoch
                // still closes to new keys once its admission window
                // lapses — the window binds submit, not just rotation.
                let opened_ms = row.open.expect("open epoch matched above").1;
                if now_ms >= opened_ms.saturating_add(EPOCH_WINDOW_MS) {
                    return Ok(SubmitOutcome::EpochClosed);
                }
            }
            Some(row) if req.epoch <= row.floor => return Ok(SubmitOutcome::EpochClosed),
            Some(_) if closed_contains(tx, scope, req.epoch)? => {
                return Ok(SubmitOutcome::EpochClosed)
            }
            _ => return Ok(SubmitOutcome::UnknownEpoch),
        }
        let records: i64 = tx.query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        let total_records = records as usize + ram_by_identity.len();
        let active: i64 = tx.query_row(
            &format!("SELECT COUNT(*) FROM operations WHERE dispatch_state IN ({ACTIVE_SQL})"),
            [],
            |row| row.get(0),
        )?;
        let mut total_active = active as usize;
        let mut principal_active = 0;
        for op in ram_by_identity.values() {
            if op.dispatch_state.is_active() {
                total_active += 1;
                if op.uid == uid {
                    principal_active += 1;
                }
            }
        }
        if total_records >= RECORD_CAP || total_active >= ACTIVE_CAP {
            return Ok(SubmitOutcome::NoCapacity);
        }
        let durable_principal: i64 = tx.query_row(
            &format!(
                "SELECT COUNT(*) FROM operations WHERE uid=?1 AND dispatch_state IN ({ACTIVE_SQL})"
            ),
            params![uid],
            |row| row.get(0),
        )?;
        if durable_principal as usize + principal_active >= ACTIVE_PER_PRINCIPAL_CAP {
            return Ok(SubmitOutcome::NoCapacity);
        }
        let seq = Self::next_seq_tx(tx)?;
        if seq == 0 || seq >= i64::MAX as u64 {
            return Ok(SubmitOutcome::NoCapacity);
        }
        tx.execute(
            "UPDATE meta SET value=?1 WHERE key='next_seq'",
            params![u64_blob(seq.saturating_add(1).max(1))],
        )?;
        let op = StoredOperation {
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
            dispatch_state: DispatchState::HostQueued,
            terminal_ms: None,
        };
        if req.storage == crate::canonical::STORAGE_RAM {
            // Staged, not inserted: the overlay gains the record only
            // after commit, so a failed commit leaves no stale shadow
            // for the rolled-back seq.
            delta.admitted = Some((identity, op));
        } else {
            tx.execute(
                "INSERT INTO operations(seq, uid, network, epoch, key, dest_kind, dest, delivery, priority, ttl_ms, storage, hop_limit, payload, canonical, hash, accepted_ms, dispatch_state, terminal_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,'HOST_QUEUED',NULL)",
                params![
                    seq as i64,
                    uid,
                    req.network as i64,
                    u64_blob(req.epoch),
                    req.key.to_vec(),
                    req.dest_kind,
                    u64_blob(req.dest),
                    req.delivery,
                    req.priority,
                    req.ttl_ms,
                    req.storage,
                    req.hop_limit,
                    req.payload,
                    req.canonical,
                    req.hash.to_vec(),
                    ms_to_db(now_ms),
                ],
            )?;
        }
        Ok(SubmitOutcome::Accepted { seq })
    }

    /// Test hook standing in for the CAP-I2/TX-I2 dispatcher; see the
    /// memory provider's hook. Persists when the record is durable.
    #[cfg(test)]
    pub fn set_state_for_test(&mut self, seq: u64, state: DispatchState, terminal_ms: Option<u64>) {
        if let Some(identity) = self.ram_by_seq.get(&seq).copied() {
            if let Some(op) = self.ram_by_identity.get_mut(&identity) {
                op.dispatch_state = state;
                op.terminal_ms = terminal_ms;
            }
            return;
        }
        let _ = self.conn.execute(
            "UPDATE operations SET dispatch_state=?1, terminal_ms=?2 WHERE seq=?3",
            params![
                state.name(),
                terminal_ms.map(ms_to_db),
                seq.min(i64::MAX as u64) as i64,
            ],
        );
    }

    /// Test hook: run the retire pass directly and report the new floor.
    #[cfg(test)]
    pub fn retire_for_test(&mut self, scope: EpochScope, now_ms: u64) -> u64 {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("retire txn");
        let mut delta = RamDelta::default();
        Self::retire_tx(&self.ram_by_identity, &mut delta, &tx, scope, now_ms).expect("retire");
        let floor = read_scope(&tx, scope)
            .expect("scope")
            .map(|row| row.floor)
            .unwrap_or(0);
        tx.commit().expect("retire commit");
        Self::apply_ram_delta(&mut self.ram_by_identity, &mut self.ram_by_seq, delta);
        floor
    }

    /// Fault injection for the commit-failure paths: veto exactly the
    /// next commit via SQLite's commit hook (a hook returning true turns
    /// the COMMIT into a ROLLBACK), then disarm.
    #[cfg(test)]
    fn veto_next_commit(&self) {
        let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.conn.commit_hook(Some(move || {
            armed.swap(false, std::sync::atomic::Ordering::Relaxed)
        }));
    }

    fn open_epoch_tx(
        ram_by_identity: &HashMap<OpIdentity, StoredOperation>,
        delta: &mut RamDelta,
        tx: &Transaction<'_>,
        scope: EpochScope,
        now_ms: u64,
    ) -> Result<Result<(u64, bool), OpenEpochError>, rusqlite::Error> {
        let (uid, network) = scope;
        if read_scope(tx, scope)?.is_none() {
            tx.execute(
                "INSERT INTO scope_epoch(uid, network, floor, next_epoch, open_epoch, open_ms) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    uid,
                    network as i64,
                    u64_blob(0),
                    u64_blob(2),
                    u64_blob(1),
                    ms_to_db(now_ms),
                ],
            )?;
            return Ok(Ok((1, true)));
        }
        Self::retire_tx(ram_by_identity, delta, tx, scope, now_ms)?;
        let row = read_scope(tx, scope)?.expect("scope read above");
        if let Some((open, opened_ms)) = row.open {
            if now_ms < opened_ms.saturating_add(EPOCH_WINDOW_MS) {
                return Ok(Ok((open, false)));
            }
            tx.execute(
                "INSERT INTO closed_epoch(uid, network, epoch) VALUES (?1,?2,?3)",
                params![uid, network as i64, u64_blob(open)],
            )?;
            tx.execute(
                "UPDATE scope_epoch SET open_epoch=NULL, open_ms=NULL WHERE uid=?1 AND network=?2",
                params![uid, network as i64],
            )?;
        }
        if unretired_count(tx, scope)? >= MAX_UNRETIRED_EPOCHS || row.next_epoch == u64::MAX {
            return Ok(Err(OpenEpochError::NoCapacity));
        }
        let epoch = row.next_epoch;
        tx.execute(
            "UPDATE scope_epoch SET next_epoch=?3, open_epoch=?4, open_ms=?5 WHERE uid=?1 AND network=?2",
            params![
                uid,
                network as i64,
                u64_blob(epoch.saturating_add(1)),
                u64_blob(epoch),
                ms_to_db(now_ms),
            ],
        )?;
        Ok(Ok((epoch, true)))
    }
}

impl OperationStore for SqliteOperationStore {
    fn lineage(&self) -> [u8; 16] {
        self.lineage
    }

    fn durable(&self) -> bool {
        true
    }

    fn open_epoch(
        &mut self,
        scope: EpochScope,
        now_ms: u64,
    ) -> Result<(u64, bool), OpenEpochError> {
        let Self {
            conn,
            ram_by_identity,
            ram_by_seq,
            ..
        } = self;
        let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(error) => {
                eprintln!("opstore fault: {error}");
                return Err(OpenEpochError::StoreFault);
            }
        };
        let mut delta = RamDelta::default();
        let outcome = match Self::open_epoch_tx(ram_by_identity, &mut delta, &tx, scope, now_ms) {
            Ok(outcome) => outcome,
            Err(error) => {
                eprintln!("opstore fault: {error}");
                return Err(OpenEpochError::StoreFault);
            }
        };
        if let Err(error) = tx.commit() {
            eprintln!("opstore fault: {error}");
            return Err(OpenEpochError::StoreFault);
        }
        Self::apply_ram_delta(ram_by_identity, ram_by_seq, delta);
        outcome
    }

    fn submit(&mut self, uid: u32, req: &SendRequest, now_ms: u64) -> SubmitOutcome {
        // Physical budget first: without a measurable store file the daemon
        // cannot vouch for durability at all.
        match store_file_bytes(&self.path) {
            Some(used) if used < STORE_BYTES_CAP => {}
            Some(_) => return SubmitOutcome::NoCapacity,
            None => {
                eprintln!(
                    "opstore fault: store file {} is unmeasurable",
                    self.path.display()
                );
                return SubmitOutcome::StoreFault;
            }
        }
        let Self {
            conn,
            ram_by_identity,
            ram_by_seq,
            ..
        } = self;
        let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(error) => return Self::fault(error),
        };
        let mut delta = RamDelta::default();
        let outcome = match Self::submit_tx(ram_by_identity, &mut delta, &tx, uid, req, now_ms) {
            Ok(outcome) => outcome,
            Err(error) => return Self::fault(error),
        };
        match tx.commit() {
            Ok(()) => {
                Self::apply_ram_delta(ram_by_identity, ram_by_seq, delta);
                outcome
            }
            Err(error) => Self::fault(error),
        }
    }

    fn get_by_seq(&self, seq: u64) -> Result<Option<StoredOperation>, ()> {
        if let Some(identity) = self.ram_by_seq.get(&seq) {
            return Ok(self.ram_by_identity.get(identity).cloned());
        }
        if seq > i64::MAX as u64 {
            return Ok(None);
        }
        self.conn
            .query_row(
                &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE seq=?1"),
                params![seq as i64],
                read_operation_row,
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
            })
    }

    fn get_by_key(&self, identity: &OpIdentity) -> Result<Option<StoredOperation>, ()> {
        if let Some(op) = self.ram_by_identity.get(identity) {
            return Ok(Some(op.clone()));
        }
        self.conn
            .query_row(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM operations WHERE uid=?1 AND network=?2 AND epoch=?3 AND key=?4"
                ),
                params![
                    identity.uid,
                    identity.network as i64,
                    u64_blob(identity.epoch),
                    identity.key.to_vec(),
                ],
                read_operation_row,
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
            })
    }

    fn capacity_status(&self, now_ms: u64) -> CapacityStatus {
        // Fail closed: any measurement fault reports zero rather than a
        // guess the daemon might admit against.
        measured_capacity(&self.conn, &self.ram_by_identity, &self.path, now_ms).unwrap_or(
            CapacityStatus {
                free_slots: 0,
                free_bytes: 0,
                reclaimable_at_ms: None,
            },
        )
    }
}

fn measured_capacity(
    conn: &Connection,
    ram: &HashMap<OpIdentity, StoredOperation>,
    path: &Path,
    now_ms: u64,
) -> Result<CapacityStatus, ()> {
    // Unmeasurable means unknowable: report zero, not a guess.
    let used = store_file_bytes(path).ok_or(())?;
    let failed = |error: rusqlite::Error| {
        eprintln!("opstore fault: {error}");
    };
    let records: i64 = conn
        .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
        .map_err(failed)?;
    let total = records as usize + ram.len();
    let cutoff = ms_to_db(now_ms.saturating_sub(RETENTION_MS));
    let durable_lapse: Option<i64> = conn
            .query_row(
                &format!(
                    "SELECT MIN(terminal_ms) FROM operations WHERE dispatch_state IN ({TERMINAL_SQL}) AND terminal_ms IS NOT NULL AND terminal_ms > ?1"
                ),
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(failed)?;
    let mut lapse = durable_lapse
        .and_then(db_to_ms)
        .map(|t| t.saturating_add(RETENTION_MS));
    for op in ram.values() {
        if !op.dispatch_state.is_terminal() {
            continue;
        }
        if let Some(end) = op.terminal_ms.map(|t| t.saturating_add(RETENTION_MS)) {
            let better = lapse.is_none() || lapse.is_some_and(|best| end < best);
            if end > now_ms && better {
                lapse = Some(end);
            }
        }
    }
    Ok(CapacityStatus {
        free_slots: RECORD_CAP.saturating_sub(total),
        free_bytes: STORE_BYTES_CAP
            .saturating_sub(used.max(total as u64 * RECORD_RESERVATION_BYTES)),
        reclaimable_at_ms: lapse,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::parse_submit;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique scratch database per test; files are removed on drop.
    struct TestDb {
        path: PathBuf,
    }

    impl TestDb {
        fn new(name: &str) -> Self {
            let id = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "routeloom-cap1-{}-{}-{id}.db",
                std::process::id(),
                name
            ));
            Self::remove(&path);
            Self { path }
        }

        fn remove(path: &Path) {
            let _ = std::fs::remove_file(path);
            for suffix in ["-wal", "-shm", "-journal"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
            }
        }

        fn open(&self) -> SqliteOperationStore {
            SqliteOperationStore::open(&self.path).expect("open test store")
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            Self::remove(&self.path);
        }
    }

    fn request(key: &str, epoch: u64, storage: &str) -> SendRequest {
        let json = format!(
            "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch:016x}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{{\"storage\":\"{storage}\"}}}}"
        );
        let mut req = parse_submit(&routeloom_json::parse(&json).unwrap()).unwrap();
        req.epoch = epoch;
        req
    }

    fn durable(key: &str, epoch: u64) -> SendRequest {
        request(key, epoch, "HOST_DURABLE")
    }

    fn ram(key: &str, epoch: u64) -> SendRequest {
        request(key, epoch, "RAM_ONLY")
    }

    fn submit(store: &mut SqliteOperationStore, uid: u32, req: &SendRequest, now: u64) -> u64 {
        match store.submit(uid, req, now) {
            SubmitOutcome::Accepted { seq } => seq,
            other => panic!("expected accept, got {}", outcome_name(&other)),
        }
    }

    fn outcome_name(outcome: &SubmitOutcome) -> &'static str {
        match outcome {
            SubmitOutcome::Accepted { .. } => "accepted",
            SubmitOutcome::Replay { .. } => "replay",
            SubmitOutcome::Conflict { .. } => "conflict",
            SubmitOutcome::UnknownEpoch => "unknown-epoch",
            SubmitOutcome::EpochClosed => "epoch-closed",
            SubmitOutcome::NoCapacity => "no-capacity",
            SubmitOutcome::StoreFault => "store-fault",
        }
    }

    /// Write → reopen → same lineage, epochs and durable records; the
    /// sequence never rewinds and RAM_ONLY records do not survive.
    #[test]
    fn roundtrip_preserves_durable_state() {
        let db = TestDb::new("roundtrip");
        let lineage;
        {
            let mut store = db.open();
            lineage = store.lineage();
            assert_eq!(store.open_epoch((501, 1), 0), Ok((1, true)));
            let durable_seq = submit(
                &mut store,
                501,
                &durable("00112233445566778899aabbccddeeff", 1),
                1000,
            );
            assert_eq!(durable_seq, 1);
            let ram_seq = submit(
                &mut store,
                501,
                &ram("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
                1000,
            );
            assert_eq!(ram_seq, 2);
            assert!(store.path.exists());
            assert!(store.capacity_status(0).free_slots == RECORD_CAP - 2);
        }
        {
            let mut store = db.open();
            assert_eq!(store.lineage(), lineage);
            // Same epoch binds without creating a new one.
            assert_eq!(store.open_epoch((501, 1), 100), Ok((1, false)));
            // Durable record intact, byte for byte.
            let op = store.get_by_seq(1).unwrap().unwrap();
            assert_eq!(op.payload, vec![0x00, 0xff]);
            assert_eq!(op.accepted_ms, 1000);
            assert_eq!(op.dispatch_state, DispatchState::HostQueued);
            let identity = OpIdentity {
                uid: 501,
                network: 1,
                epoch: 1,
                key: durable("00112233445566778899aabbccddeeff", 1).key,
            };
            assert_eq!(store.get_by_key(&identity).unwrap().unwrap().seq, 1);
            // Replay after restart returns the same id, not a new record.
            match store.submit(501, &durable("00112233445566778899aabbccddeeff", 1), 2000) {
                SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
                other => panic!("expected replay, got {}", outcome_name(&other)),
            }
            // RAM_ONLY record is gone — and its sequence is not reused.
            assert!(store.get_by_seq(2).unwrap().is_none());
            let seq = submit(
                &mut store,
                501,
                &durable("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
                2000,
            );
            assert_eq!(seq, 3);
        }
    }

    /// Same replay/conflict/epoch semantics as the memory provider.
    #[test]
    fn replay_conflict_and_epoch_parity() {
        let db = TestDb::new("parity");
        let mut store = db.open();
        store.open_epoch((501, 1), 0).unwrap();
        let first = durable("00112233445566778899aabbccddeeff", 1);
        assert_eq!(submit(&mut store, 501, &first, 1000), 1);
        match store.submit(501, &first, 2000) {
            SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
            other => panic!("expected replay, got {}", outcome_name(&other)),
        }
        // Same key, different payload conflicts and preserves the original.
        let mut alt = durable("00112233445566778899aabbccddeeff", 1);
        alt.payload = vec![0x99];
        alt.canonical = crate::canonical::canonical_bytes(1, 0, 3, 1, 1, 1, 5000, 10, &alt.payload);
        alt.hash = crate::canonical::sha256(&alt.canonical);
        match store.submit(501, &alt, 2000) {
            SubmitOutcome::Conflict { existing_seq } => assert_eq!(existing_seq, 1),
            other => panic!("expected conflict, got {}", outcome_name(&other)),
        }
        assert_eq!(
            store.get_by_seq(1).unwrap().unwrap().payload,
            vec![0x00, 0xff]
        );
        // RAM overlay participates in identity too: same key can never be
        // admitted twice with different bytes, whichever side holds it.
        let ram_req = ram("cccccccccccccccccccccccccccccccc", 1);
        assert_eq!(submit(&mut store, 501, &ram_req, 1000), 2);
        let mut ram_alt = ram_req;
        ram_alt.payload = vec![0x99];
        ram_alt.canonical =
            crate::canonical::canonical_bytes(1, 0, 3, 1, 1, 0, 5000, 10, &ram_alt.payload);
        ram_alt.hash = crate::canonical::sha256(&ram_alt.canonical);
        match store.submit(501, &ram_alt, 2000) {
            SubmitOutcome::Conflict { existing_seq } => assert_eq!(existing_seq, 2),
            other => panic!("expected conflict, got {}", outcome_name(&other)),
        }
        // Cross-class: the same key as HOST_DURABLE disagrees with the
        // stored RAM_ONLY bytes (storage is canonical input) — conflict,
        // still pointing at the original record.
        match store.submit(501, &durable("cccccccccccccccccccccccccccccccc", 1), 2000) {
            SubmitOutcome::Conflict { existing_seq } => assert_eq!(existing_seq, 2),
            other => panic!("expected conflict, got {}", outcome_name(&other)),
        }
        // Never-issued epoch stays unknown.
        assert!(matches!(
            store.submit(501, &durable("dddddddddddddddddddddddddddddddd", 9), 1000),
            SubmitOutcome::UnknownEpoch
        ));
    }

    /// CAP04 on the durable path: rotation persists, closed epochs fail
    /// closed across restarts, known keys stay answerable.
    #[test]
    fn durable_epoch_close_survives_restart() {
        let db = TestDb::new("epochclose");
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            submit(
                &mut store,
                501,
                &durable("00112233445566778899aabbccddeeff", 1),
                100,
            );
            assert_eq!(store.open_epoch((501, 1), EPOCH_WINDOW_MS), Ok((2, true)));
        }
        {
            let mut store = db.open();
            // Still epoch 2 after the restart — no rotation replayed.
            assert_eq!(
                store.open_epoch((501, 1), EPOCH_WINDOW_MS + 1),
                Ok((2, false))
            );
            assert!(matches!(
                store.submit(501, &durable("ffffffffffffffffffffffffffffffff", 1), 0),
                SubmitOutcome::EpochClosed
            ));
            match store.submit(501, &durable("00112233445566778899aabbccddeeff", 1), 0) {
                SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
                other => panic!("expected replay, got {}", outcome_name(&other)),
            }
        }
    }

    /// CAP05 on the durable path: contiguity, floor persistence and the
    /// indeterminate pin, all visible after a restart.
    #[test]
    fn durable_retire_pins_and_persists_floor() {
        let db = TestDb::new("retire");
        let scope = (501, 1);
        {
            let mut store = db.open();
            for epoch in 1..=3 {
                store
                    .open_epoch(scope, (epoch - 1) * EPOCH_WINDOW_MS)
                    .unwrap();
                if epoch < 3 {
                    submit(
                        &mut store,
                        501,
                        &durable(&format!("{epoch:032x}"), epoch),
                        0,
                    );
                }
            }
            store.set_state_for_test(1, DispatchState::EndSdkReceived, Some(0));
            store.set_state_for_test(2, DispatchState::Indeterminate, None);
            assert_eq!(store.retire_for_test(scope, RETENTION_MS), 1);
        }
        {
            let mut store = db.open();
            // Floor 1 persisted; epoch 2 still pinned by the indeterminate
            // record, which reloaded untouched — never reissued.
            let op = store.get_by_seq(2).unwrap().unwrap();
            assert_eq!(op.dispatch_state, DispatchState::Indeterminate);
            assert_eq!(store.retire_for_test(scope, 10 * RETENTION_MS), 1);
            assert!(matches!(
                store.submit(501, &durable(&format!("{:032x}", 1), 1), 0),
                SubmitOutcome::EpochClosed
            ));
        }
    }

    /// A record caught mid-dispatch at shutdown reloads as indeterminate;
    /// queued, terminal and indeterminate records reload untouched.
    #[test]
    fn restart_recovers_prepared_as_indeterminate() {
        let db = TestDb::new("recovery");
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            submit(
                &mut store,
                501,
                &durable("11111111111111111111111111111111", 1),
                0,
            );
            submit(
                &mut store,
                501,
                &durable("22222222222222222222222222222222", 1),
                0,
            );
            submit(
                &mut store,
                501,
                &durable("33333333333333333333333333333333", 1),
                0,
            );
            submit(
                &mut store,
                501,
                &durable("44444444444444444444444444444444", 1),
                0,
            );
            store.set_state_for_test(2, DispatchState::DispatchPrepared, None);
            store.set_state_for_test(3, DispatchState::EndSdkReceived, Some(500));
            store.set_state_for_test(4, DispatchState::Indeterminate, None);
        }
        {
            let store = db.open();
            assert_eq!(
                store.get_by_seq(1).unwrap().unwrap().dispatch_state,
                DispatchState::HostQueued
            );
            assert_eq!(
                store.get_by_seq(2).unwrap().unwrap().dispatch_state,
                DispatchState::Indeterminate
            );
            let terminal = store.get_by_seq(3).unwrap().unwrap();
            assert_eq!(terminal.dispatch_state, DispatchState::EndSdkReceived);
            assert_eq!(terminal.terminal_ms, Some(500));
            assert_eq!(
                store.get_by_seq(4).unwrap().unwrap().dispatch_state,
                DispatchState::Indeterminate
            );
        }
    }

    /// Suspect files refuse to open: garbage, a foreign SQLite schema, a
    /// bumped version and a pre-existing empty file never become a live
    /// store, and the daemon would exit instead of minting over them.
    #[test]
    fn suspect_files_refuse_to_open() {
        // Random bytes are not a database.
        let garbage = TestDb::new("garbage");
        std::fs::write(&garbage.path, vec![0xA5u8; 512]).unwrap();
        let err = SqliteOperationStore::open(&garbage.path).unwrap_err();
        assert!(err.message.contains("STORE_RECOVERY_REQUIRED"), "{err}");
        // A valid SQLite file with no store schema.
        let foreign = TestDb::new("foreign");
        {
            let conn = rusqlite::Connection::open(&foreign.path).unwrap();
            conn.execute_batch("CREATE TABLE other(x);").unwrap();
        }
        let err = SqliteOperationStore::open(&foreign.path).unwrap_err();
        assert!(err.message.contains("STORE_RECOVERY_REQUIRED"), "{err}");
        // Unknown schema version is never migrated or erased in place.
        let versioned = TestDb::new("versioned");
        {
            let store = versioned.open();
            drop(store);
            let conn = rusqlite::Connection::open(&versioned.path).unwrap();
            conn.execute(
                "UPDATE meta SET value=?1 WHERE key='schema_version'",
                params![99u32.to_be_bytes().to_vec()],
            )
            .unwrap();
        }
        let err = SqliteOperationStore::open(&versioned.path).unwrap_err();
        assert!(err.message.contains("STORE_RECOVERY_REQUIRED"), "{err}");
        // A pre-existing empty file is not silently adopted as fresh.
        let empty = TestDb::new("empty");
        std::fs::write(&empty.path, []).unwrap();
        let err = SqliteOperationStore::open(&empty.path).unwrap_err();
        assert!(err.message.contains("STORE_RECOVERY_REQUIRED"), "{err}");
    }

    /// An uncommitted admission never surfaces: dropping the transaction
    /// rolls it back and the reopened store is consistent.
    #[test]
    fn uncommitted_write_never_surfaces() {
        let db = TestDb::new("torn");
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            submit(
                &mut store,
                501,
                &durable("00112233445566778899aabbccddeeff", 1),
                0,
            );
        }
        {
            let mut conn = rusqlite::Connection::open(&db.path).unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO operations(seq, uid, network, epoch, key, dest_kind, dest, delivery, priority, ttl_ms, storage, hop_limit, payload, canonical, hash, accepted_ms, dispatch_state, terminal_ms) VALUES (99,501,1,?1,?2,0,?3,1,1,5000,1,10,x'00',x'00',?4,0,'HOST_QUEUED',NULL)",
                params![
                    u64_blob(1),
                    vec![0xeeu8; 16],
                    u64_blob(3),
                    vec![0xabu8; 32],
                ],
            )
            .unwrap();
            drop(tx); // no commit: crash-equivalent rollback
        }
        {
            let store = db.open();
            assert!(store.get_by_seq(99).unwrap().is_none());
            assert!(store.get_by_seq(1).unwrap().is_some());
        }
    }

    /// CAP01 on the durable path: a full table rejects without evicting.
    /// Prefilled in one transaction to keep the test fast; the quota
    /// check itself runs through the normal submit path.
    #[test]
    fn full_table_rejects_without_eviction() {
        let db = TestDb::new("full");
        {
            let store = db.open();
            drop(store);
            let mut conn = rusqlite::Connection::open(&db.path).unwrap();
            let tx = conn.transaction().unwrap();
            for seq in 1..RECORD_CAP as i64 {
                let key = (seq as u128).to_be_bytes().to_vec();
                tx.execute(
                    "INSERT INTO operations(seq, uid, network, epoch, key, dest_kind, dest, delivery, priority, ttl_ms, storage, hop_limit, payload, canonical, hash, accepted_ms, dispatch_state, terminal_ms) VALUES (?1,501,1,?2,?3,0,?4,1,1,5000,1,10,x'',x'',?5,0,'HOST_QUEUED',NULL)",
                    params![
                        seq,
                        u64_blob(1),
                        key,
                        u64_blob(3),
                        vec![0xabu8; 32],
                    ],
                )
                .unwrap();
            }
            tx.execute(
                "UPDATE meta SET value=?1 WHERE key='next_seq'",
                params![u64_blob(RECORD_CAP as u64)],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            let last = durable("fffffffffffffffffffffffffffffff0", 1);
            match store.submit(501, &last, 0) {
                SubmitOutcome::Accepted { seq } => assert_eq!(seq, RECORD_CAP as u64),
                other => panic!("expected accept, got {}", outcome_name(&other)),
            }
            let extra = durable("fffffffffffffffffffffffffffffff1", 1);
            assert!(matches!(
                store.submit(501, &extra, 0),
                SubmitOutcome::NoCapacity
            ));
            assert!(store.get_by_seq(1).unwrap().is_some());
            assert!(store.get_by_seq(RECORD_CAP as u64).unwrap().is_some());
            let status = store.capacity_status(0);
            assert_eq!(status.free_slots, 0);
            assert_eq!(status.reclaimable_at_ms, None);
        }
    }

    /// Active quotas span durable rows and the RAM overlay together.
    #[test]
    fn active_quota_spans_both_sides() {
        let db = TestDb::new("active");
        let mut store = db.open();
        store.open_epoch((501, 1), 0).unwrap();
        for i in 0..ACTIVE_PER_PRINCIPAL_CAP {
            let seq = if i % 2 == 0 {
                submit(&mut store, 501, &durable(&format!("{i:032x}"), 1), 0)
            } else {
                submit(&mut store, 501, &ram(&format!("{i:032x}"), 1), 0)
            };
            store.set_state_for_test(seq, DispatchState::DispatchPrepared, None);
        }
        assert!(matches!(
            store.submit(501, &durable("ffffffffffffffffffffffffffffffff", 1), 0),
            SubmitOutcome::NoCapacity
        ));
    }

    /// Store footprint sums the main file and WAL sidecars; a missing
    /// main file is unmeasurable, never zero.
    #[test]
    fn file_bytes_sum_sidecars() {
        let dir = std::env::temp_dir().join(format!("routeloom-cap1-bytes-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let main = dir.join("store.db");
        std::fs::write(&main, vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("store.db-wal"), vec![0u8; 25]).unwrap();
        std::fs::write(dir.join("store.db-shm"), vec![0u8; 7]).unwrap();
        assert_eq!(store_file_bytes(&main), Some(132));
        assert_eq!(store_file_bytes(&dir.join("missing.db")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CAP04 on the durable path: the hourly window binds submit itself —
    /// an epoch past its admission window but not yet rotated rejects new
    /// keys, and the persisted open_ms keeps that rule across a restart.
    #[test]
    fn expired_epoch_rejects_new_keys_before_rotation() {
        let db = TestDb::new("epochwindow");
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            submit(
                &mut store,
                501,
                &durable("00112233445566778899aabbccddeeff", 1),
                0,
            );
            // Last instant inside the window still admits.
            submit(
                &mut store,
                501,
                &ram("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
                EPOCH_WINDOW_MS - 1,
            );
            // At and past the window a new key fails closed even though
            // no rotation ran.
            for now in [EPOCH_WINDOW_MS, EPOCH_WINDOW_MS + 60_000] {
                assert!(matches!(
                    store.submit(501, &durable("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1), now),
                    SubmitOutcome::EpochClosed
                ));
            }
            // The known key still replays inside the expired epoch.
            match store.submit(
                501,
                &durable("00112233445566778899aabbccddeeff", 1),
                EPOCH_WINDOW_MS + 1,
            ) {
                SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
                other => panic!("expected replay, got {}", outcome_name(&other)),
            }
        }
        // open_ms is persisted: a restart does not reopen the window.
        {
            let mut store = db.open();
            assert!(matches!(
                store.submit(
                    501,
                    &durable("cccccccccccccccccccccccccccccccc", 1),
                    EPOCH_WINDOW_MS
                ),
                SubmitOutcome::EpochClosed
            ));
            assert_eq!(store.open_epoch((501, 1), EPOCH_WINDOW_MS), Ok((2, true)));
            assert_eq!(
                submit(
                    &mut store,
                    501,
                    &durable("dddddddddddddddddddddddddddddddd", 2),
                    EPOCH_WINDOW_MS
                ),
                3
            );
        }
    }

    /// A foreign principal's RAM record in the same network+epoch must
    /// not pin another scope's retire pass.
    #[test]
    fn foreign_ram_record_does_not_block_retire() {
        let db = TestDb::new("foreignram");
        let mut store = db.open();
        // Two scopes share network 1; epochs are tracked per scope.
        store.open_epoch((501, 1), 0).unwrap();
        store.open_epoch((7, 1), 0).unwrap();
        // uid 501's RAM record stays live — it would block retire if the
        // overlay scan ignored uid.
        let ram_seq = submit(
            &mut store,
            501,
            &ram("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
            0,
        );
        // uid 7's durable record completes and lapses.
        let done = submit(
            &mut store,
            7,
            &durable("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
            0,
        );
        store.set_state_for_test(done, DispatchState::EndSdkReceived, Some(0));
        store.open_epoch((7, 1), EPOCH_WINDOW_MS).unwrap();
        // Scope (7,1) epoch 1 retires despite 501's live RAM record.
        assert_eq!(store.retire_for_test((7, 1), RETENTION_MS), 1);
        assert!(store.get_by_seq(done).unwrap().is_none());
        // 501's record is untouched in its own scope.
        assert_eq!(store.get_by_seq(ram_seq).unwrap().unwrap().uid, 501);
    }

    /// A vetoed commit must leave no RAM residue: the record never
    /// becomes queryable and the rolled-back seq is reissued without a
    /// stale overlay shadow.
    #[test]
    fn failed_commit_leaves_no_ram_record() {
        let db = TestDb::new("commitfail");
        let mut store = db.open();
        store.open_epoch((501, 1), 0).unwrap();
        let req = ram("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
        store.veto_next_commit();
        assert!(matches!(
            store.submit(501, &req, 0),
            SubmitOutcome::StoreFault
        ));
        let identity = OpIdentity {
            uid: 501,
            network: 1,
            epoch: 1,
            key: req.key,
        };
        assert!(store.get_by_key(&identity).unwrap().is_none());
        assert!(store.get_by_seq(1).unwrap().is_none());
        // The rolled-back seq reissues cleanly: the next admission is a
        // different (durable) record and must not be shadowed by the
        // aborted RAM one — replaying the aborted key does not resolve
        // to it either.
        let next = durable("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1);
        assert_eq!(submit(&mut store, 501, &next, 1), 1);
        let op = store.get_by_seq(1).unwrap().unwrap();
        assert_eq!(op.key, next.key);
        assert!(matches!(
            store.submit(501, &req, 2),
            SubmitOutcome::Accepted { seq: 2 }
        ));
    }

    /// A vetoed commit inside the retire pass must not drop overlay
    /// records either: the rolled-back retirement leaves the RAM record
    /// in place until a later commit retires it for real. (open_epoch is
    /// the trigger — by the time protection lapses, any newer epoch's
    /// own window has closed to submits.)
    #[test]
    fn failed_commit_rolls_back_ram_retire() {
        let db = TestDb::new("commitfailretire");
        let mut store = db.open();
        store.open_epoch((501, 1), 0).unwrap();
        let req = ram("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
        let seq = submit(&mut store, 501, &req, 0);
        store.set_state_for_test(seq, DispatchState::EndSdkReceived, Some(0));
        store.open_epoch((501, 1), EPOCH_WINDOW_MS).unwrap();
        let identity = OpIdentity {
            uid: 501,
            network: 1,
            epoch: 1,
            key: req.key,
        };
        // The rotation transaction carries the retire pass over the
        // lapsed epoch; vetoing its commit rolls everything back.
        store.veto_next_commit();
        assert!(matches!(
            store.open_epoch((501, 1), EPOCH_WINDOW_MS + RETENTION_MS),
            Err(OpenEpochError::StoreFault)
        ));
        assert!(store.get_by_key(&identity).unwrap().is_some());
        // The retry commits the same retire for real: the contiguous
        // prefix (epochs 1 and the empty 2) both advance the floor.
        assert_eq!(
            store.open_epoch((501, 1), EPOCH_WINDOW_MS + RETENTION_MS),
            Ok((3, true))
        );
        assert!(store.get_by_key(&identity).unwrap().is_none());
        assert_eq!(
            store.retire_for_test((501, 1), EPOCH_WINDOW_MS + RETENTION_MS),
            2
        );
    }
}
