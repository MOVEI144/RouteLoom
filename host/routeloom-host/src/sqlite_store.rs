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
//!
//! Two restart/failure rules deserve their own mention. First, the RAM_ONLY
//! dedup map is volatile by contract (04-capacity-storage.md §3 — no
//! guarantee across a daemon stop), so a restart cannot tell a resubmitted
//! RAM_ONLY key from a new one while its accept-epoch is still open. The
//! store therefore seals every still-open epoch in one transaction at open:
//! resubmitted keys fail closed with EPOCH_CLOSED, durable records keep
//! answering Replay/get_by_key, and new sends mint a fresh epoch — never a
//! second execution under a recycled identity. Second, payloads live in the
//! DB file AND its WAL/journal sidecars, so the file is created owner-only
//! before SQLite ever sees the path (the unix VFS derives sidecar modes
//! from the main file) and every file is chmod 0600 again once sidecars
//! exist — a chmod failure refuses startup rather than leaving the WAL
//! readable by a different UID behind the API ACL's back.

use crate::canonical::SendRequest;
use crate::send_store::{
    mint_id128, CapacityStatus, DispatchAttachment, DispatchState, EpochScope, IssueIdentity,
    IssueRefusal, OpIdentity, OpenEpochError, OperationStore, PrepareOutcome, StoredOperation,
    SubmitOutcome, ACTIVE_CAP, ACTIVE_PER_PRINCIPAL_CAP, EPOCH_WINDOW_MS, ISSUE_OUTBOX_CAP,
    MAX_UNRETIRED_EPOCHS, RECORD_CAP, RECORD_RESERVATION_BYTES, RETENTION_MS, STORE_BYTES_CAP,
};
use routeloom_peercred::Principal;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Schema v2 added the TX-I2 `operations.dispatch` attachment. Schema v3
/// added the bounded config outbox and its terminal marker. Schema v4
/// stores versioned principals; v1-v3 files migrate atomically.
const SCHEMA_VERSION: u32 = 4;

/// Mirror of the device dispatch window (contracts `DISPATCH_WINDOW`,
/// kept in `dispatch.rs`): lane positions further than this below the
/// persisted allocator top were necessarily under the device floor at
/// the last shutdown, so tombstone recovery only rebuilds the top of
/// the consumed range.
const LANE_HOLE_WINDOW: u64 = 32;

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scope_epoch(
    uid TEXT NOT NULL, network INTEGER NOT NULL,
    floor BLOB NOT NULL, next_epoch BLOB NOT NULL,
    open_epoch BLOB, open_ms INTEGER,
    PRIMARY KEY(uid, network));
CREATE TABLE IF NOT EXISTS closed_epoch(
    uid TEXT NOT NULL, network INTEGER NOT NULL, epoch BLOB NOT NULL,
    PRIMARY KEY(uid, network, epoch));
CREATE TABLE IF NOT EXISTS operations(
    seq INTEGER PRIMARY KEY,
    uid TEXT NOT NULL, network INTEGER NOT NULL,
    epoch BLOB NOT NULL, key BLOB NOT NULL,
    dest_kind INTEGER NOT NULL, dest BLOB NOT NULL,
    delivery INTEGER NOT NULL, priority INTEGER NOT NULL,
    ttl_ms INTEGER NOT NULL, storage INTEGER NOT NULL, hop_limit INTEGER NOT NULL,
    payload BLOB NOT NULL, canonical BLOB NOT NULL, hash BLOB NOT NULL,
    accepted_ms INTEGER NOT NULL,
    dispatch_state TEXT NOT NULL DEFAULT 'HOST_QUEUED',
    terminal_ms INTEGER,
    dispatch BLOB,
    UNIQUE(uid, network, epoch, key));
CREATE INDEX IF NOT EXISTS idx_operations_scope_epoch
    ON operations(uid, network, epoch);
";

const CONFIG_OUTBOX_SQL: &str = "
CREATE TABLE IF NOT EXISTS config_outbox(
    opid BLOB PRIMARY KEY,
    kind INTEGER NOT NULL, target BLOB NOT NULL, ns INTEGER NOT NULL,
    profile INTEGER NOT NULL, authority BLOB NOT NULL,
    generation INTEGER NOT NULL, network BLOB NOT NULL,
    sequence BLOB NOT NULL, canonical BLOB,
    signed BLOB, terminal INTEGER NOT NULL DEFAULT 0);
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

/// Footprint of the live store: main file plus journal/WAL sidecars.
/// None when the main file cannot be measured — the daemon then cannot
/// vouch for durability and must stop admitting rather than guess.
/// Sidecar names are built as OsString suffixes so a non-UTF-8 store
/// path still measures the real files (`path.display()` would not).
fn store_file_bytes(path: &Path) -> Option<u64> {
    let mut total = std::fs::metadata(path).ok()?.len();
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        total += std::fs::metadata(sidecar).map(|m| m.len()).unwrap_or(0);
    }
    Some(total)
}

/// Owner-only mode on the store file and every sidecar SQLite may have
/// created (-wal, -shm, -journal). Payloads live in these files and the
/// WAL is addressed by page, not by the API ACL — a permissive umask at
/// creation would leave them readable by a different UID, which is an
/// ACL bypass, not a hygiene issue. The main file must exist and take
/// the mode; missing sidecars are skipped; any other failure refuses
/// startup — never warn-and-continue on a store holding payloads.
#[cfg(unix)]
fn enforce_owner_only(path: &Path) -> Result<(), OpenError> {
    use std::os::unix::fs::PermissionsExt;
    let chmod = |target: PathBuf, required: bool| -> Result<(), OpenError> {
        match std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => Ok(()),
            Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: cannot make {} owner-only: {e}",
                    target.display()
                ),
            }),
        }
    };
    chmod(path.to_path_buf(), true)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        chmod(PathBuf::from(sidecar), false)?;
    }
    Ok(())
}

#[cfg(windows)]
fn enforce_owner_only(path: &Path) -> Result<(), OpenError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    routeloom_peercred::verify_private_dir_perms(parent).map_err(|e| OpenError {
        message: format!(
            "STORE_RECOVERY_REQUIRED: operation store directory {} is not private: {e}",
            parent.display()
        ),
    })?;
    for (index, suffix) in ["", "-wal", "-shm", "-journal"].iter().enumerate() {
        let mut target = path.as_os_str().to_os_string();
        target.push(suffix);
        let target = PathBuf::from(target);
        if index != 0 && target.exists() {
            routeloom_peercred::protect_private_sidecar(&target).map_err(|e| OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: cannot protect operation store sidecar {}: {e}",
                    target.display()
                ),
            })?;
        }
        match routeloom_peercred::verify_private_file_perms(&target) {
            Ok(()) => {}
            Err(e) if index != 0 && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(OpenError {
                    message: format!(
                        "STORE_RECOVERY_REQUIRED: operation store file {} is not private: {e}",
                        target.display()
                    ),
                })
            }
        }
    }
    Ok(())
}

struct ScopeRow {
    floor: u64,
    next_epoch: u64,
    open: Option<(u64, u64)>,
}

type ScopeRowParts = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<i64>);

fn read_scope(
    tx: &Transaction<'_>,
    scope: &EpochScope,
) -> Result<Option<ScopeRow>, rusqlite::Error> {
    let (uid, network) = scope;
    let row: Option<ScopeRowParts> = tx
        .query_row(
            "SELECT floor, next_epoch, open_epoch, open_ms FROM scope_epoch WHERE uid=?1 AND network=?2",
            params![uid.storage_key(), *network as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(floor, next, open, open_ms)| {
        let field = |name: &'static str| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, name.into())
        };
        // The open pair is all-or-nothing: a half-set or undecodable open
        // field is corruption — absorbing it would leave an orphaned
        // epoch that never closes and stalls the retire floor.
        let open = match (open, open_ms) {
            (None, None) => None,
            (Some(epoch), Some(ms)) => Some((
                blob_u64(epoch).ok_or_else(|| field("open_epoch"))?,
                db_to_ms(ms).ok_or_else(|| field("open_ms"))?,
            )),
            _ => return Err(field("open_epoch")),
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
    scope: &EpochScope,
) -> Result<Option<(u64, u64)>, rusqlite::Error> {
    Ok(read_scope(tx, scope)?.and_then(|row| row.open))
}

fn closed_contains(
    tx: &Transaction<'_>,
    scope: &EpochScope,
    epoch: u64,
) -> Result<bool, rusqlite::Error> {
    let (uid, network) = scope;
    Ok(tx
        .query_row(
            "SELECT 1 FROM closed_epoch WHERE uid=?1 AND network=?2 AND epoch=?3",
            params![uid.storage_key(), *network as i64, u64_blob(epoch)],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn unretired_count(tx: &Transaction<'_>, scope: &EpochScope) -> Result<usize, rusqlite::Error> {
    let (uid, network) = scope;
    let closed: i64 = tx.query_row(
        "SELECT COUNT(*) FROM closed_epoch WHERE uid=?1 AND network=?2",
        params![uid.storage_key(), *network as i64],
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
    let dispatch_raw: Option<Vec<u8>> = row.get(18)?;
    let dispatch = match dispatch_raw {
        None => None,
        Some(raw) => Some(DispatchAttachment::decode(&raw).ok_or_else(|| corrupt("dispatch"))?),
    };
    // Integer fields were `as`-cast once — silent truncation could
    // re-attribute a record (e.g. a wrapped uid passing a cancel
    // ownership check), so out-of-range values are corruption instead.
    let int_u64 = |col: usize, name: &'static str| {
        u64::try_from(row.get::<_, i64>(col)?).map_err(|_| corrupt(name))
    };
    let int_u32 = |col: usize, name: &'static str| {
        u32::try_from(row.get::<_, i64>(col)?).map_err(|_| corrupt(name))
    };
    let int_u8 = |col: usize, name: &'static str| {
        u8::try_from(row.get::<_, i64>(col)?).map_err(|_| corrupt(name))
    };
    Ok(StoredOperation {
        seq: int_u64(0, "seq")?,
        principal: Principal::from_storage_key(&row.get::<_, String>(1)?)
            .map_err(|_| corrupt("uid"))?,
        network: int_u64(2, "network")?,
        epoch,
        key,
        dest_kind: int_u8(5, "dest_kind")?,
        dest,
        delivery: int_u8(7, "delivery")?,
        priority: int_u8(8, "priority")?,
        ttl_ms: int_u32(9, "ttl_ms")?,
        storage: int_u8(10, "storage")?,
        hop_limit: int_u8(11, "hop_limit")?,
        payload: row.get(12)?,
        canonical: row.get(13)?,
        hash,
        accepted_ms: db_to_ms(row.get::<_, i64>(15)?).ok_or_else(|| corrupt("accepted_ms"))?,
        // Filled by the caller from `mono_anchor`: the stamp is volatile
        // by design, never persisted.
        accepted_mono_ms: 0,
        dispatch_state: DispatchState::parse(&state_text)
            .ok_or_else(|| corrupt("dispatch_state"))?,
        terminal_ms,
        dispatch,
    })
}

const OPERATION_COLUMNS: &str = "seq, uid, network, epoch, key, dest_kind, dest, delivery, priority, ttl_ms, storage, hop_limit, payload, canonical, hash, accepted_ms, dispatch_state, terminal_ms, dispatch";

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
    /// Whether `open` minted this file (and therefore the lineage): a new
    /// lineage is a new dispatcher id on the wire, so any gateway lane
    /// still bound under a lost store's lineage rejects every dispatch
    /// verb until the device reboots — the caller warns. False whenever
    /// an existing store file was reopened.
    created_fresh: bool,
    conn: Connection,
    ram_by_identity: HashMap<OpIdentity, StoredOperation>,
    ram_by_seq: HashMap<u64, OpIdentity>,
    /// Payload-free stand-ins for lane positions a RAM_ONLY binding
    /// consumed before the last shutdown: the volatile attachment is
    /// gone but the durable allocator's `dispatch_next` bump is not,
    /// leaving a seq no record could settle — the retire floor would
    /// wedge behind it forever. Each tombstone is already concluded and
    /// marked `submitted` (the lost claim is unknowable), so the query
    /// pass resolves the position or a SKIP proves it empty. Rebuilt at
    /// open, keyed by `u64::MAX - dispatch_seq` — outside every real
    /// sequence space.
    lane_tombstones: HashMap<u64, StoredOperation>,
    /// Monotonic admit stamps for durable records this boot (seq → mono
    /// ms). Deliberately volatile: a monotonic clock is meaningless across
    /// a restart, so reopened rows read back `accepted_mono_ms == 0` and
    /// keep the pre-anchor wall-clock deadline semantics. RAM-overlay
    /// records carry the stamp on the struct itself.
    mono_anchor: HashMap<u64, u64>,
}

impl std::fmt::Debug for SqliteOperationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteOperationStore")
            .field("path", &self.path)
            .field("lineage", &self.lineage)
            .field("ram_records", &self.ram_by_identity.len())
            .field("lane_tombstones", &self.lane_tombstones.len())
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
                #[cfg(unix)]
                std::fs::create_dir_all(parent).map_err(|e| OpenError {
                    message: format!(
                        "STORE_RECOVERY_REQUIRED: cannot create store directory {}: {e}",
                        parent.display()
                    ),
                })?;
                #[cfg(windows)]
                routeloom_peercred::create_private_dir_all(parent).map_err(|e| OpenError {
                    message: format!(
                        "STORE_RECOVERY_REQUIRED: cannot create private store directory {}: {e}",
                        parent.display()
                    ),
                })?;
            }
            // Create the file owner-only BEFORE SQLite ever opens the
            // path: the unix VFS derives the -wal/-shm/-journal modes
            // from the main file at creation, so a 0600 main file keeps
            // the sidecars owner-only from birth instead of for the
            // window between WAL setup and a later chmod. create_new
            // keeps a path that appeared since `fresh` fatal.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| OpenError {
                        message: format!(
                            "STORE_RECOVERY_REQUIRED: cannot create operation store {}: {e}",
                            path.display()
                        ),
                    })?;
            }
            #[cfg(windows)]
            routeloom_peercred::open_private_file_for_write(path).map_err(|e| OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: cannot create private operation store {}: {e}",
                    path.display()
                ),
            })?;
        }
        let mut conn = Connection::open(path).map_err(|e| OpenError {
            message: format!(
                "STORE_RECOVERY_REQUIRED: cannot open operation store {}: {e}",
                path.display()
            ),
        })?;
        // Single-writer: locks are taken once and never released, so a
        // second daemon opening the same file fails fast instead of
        // racing recovery, RAM overlays and the rate budget. The short
        // initial timeout makes that second opener fail fast; the
        // steady-state timeout is restored once ownership is proven.
        conn.pragma_update(None, "busy_timeout", 100)?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        // Prove ownership read-only BEFORE any write: journal_mode=WAL
        // rewrites the file header, so a foreign file must be refused
        // while it is still untouched.
        let version: Option<u32> = if fresh {
            None
        } else {
            let raw: Vec<u8> = conn
                .query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| OpenError {
                    message: format!(
                        "STORE_RECOVERY_REQUIRED: {} is not a RouteLoom operation store ({e})",
                        path.display()
                    ),
                })?;
            match <[u8; 4]>::try_from(raw.as_slice())
                .ok()
                .map(u32::from_be_bytes)
            {
                Some(v) if (1..=SCHEMA_VERSION).contains(&v) => Some(v),
                _ => {
                    return Err(OpenError {
                        message: format!(
                            "STORE_RECOVERY_REQUIRED: {} has an unknown store schema; refusing to erase or migrate it",
                            path.display()
                        ),
                    });
                }
            }
        };
        // Tighten a validated existing file (and any sidecars left by an
        // older version) BEFORE journal_mode=WAL: SQLite derives the mode
        // of sidecars it creates from the main file, so this is the last
        // point where that inheritance is still controllable. Fresh files
        // were already born 0600 above; chmod failure refuses startup.
        enforce_owner_only(path)?;
        // WAL where the filesystem allows it, rollback journal otherwise —
        // either is durable with FULL synchronous. Under EXCLUSIVE locking
        // a second opener fails here (or on the probe above under WAL)
        // with a lock error.
        let _journal: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(|e| OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: cannot take exclusive ownership of {}: {e}",
                    path.display()
                ),
            })?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        if fresh {
            // One transaction: a crash mid-init rolls everything back, so
            // the path is never wedged by a half-written store (version
            // and lineage set, next_seq missing).
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(SCHEMA_SQL)?;
            tx.execute_batch(CONFIG_OUTBOX_SQL)?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION.to_be_bytes().to_vec()],
            )?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('lineage', ?1)",
                params![mint_id128().to_vec()],
            )?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('next_seq', ?1)",
                params![u64_blob(1)],
            )?;
            tx.commit()?;
            // The records pay fsync for durability; the create itself
            // must too — a power loss that orphans the file after it was
            // fsync'd would mint a second lineage at the next open
            // instead of refusing.
            #[cfg(unix)]
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        match version {
            None | Some(SCHEMA_VERSION) => {}
            // v4 keeps ownership as a versioned principal string. The
            // conversion is atomic with the older schema additions.
            Some(1) | Some(2) | Some(3) => {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let has_dispatch: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('operations') WHERE name='dispatch'",
                    [],
                    |row| row.get(0),
                )?;
                if has_dispatch == 0 {
                    tx.execute("ALTER TABLE operations ADD COLUMN dispatch BLOB", [])?;
                }
                tx.execute_batch(CONFIG_OUTBOX_SQL)?;
                let has_terminal: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('config_outbox') WHERE name='terminal'",
                    [],
                    |row| row.get(0),
                )?;
                if has_terminal == 0 {
                    tx.execute(
                        "ALTER TABLE config_outbox ADD COLUMN terminal INTEGER NOT NULL DEFAULT 0",
                        [],
                    )?;
                }
                for table in ["scope_epoch", "closed_epoch", "operations"] {
                    let invalid: i64 = tx.query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE typeof(uid)!='integer' OR uid<0 OR uid>4294967295"),
                        [],
                        |row| row.get(0),
                    )?;
                    if invalid != 0 {
                        return Err(OpenError {
                            message: format!("STORE_RECOVERY_REQUIRED: invalid uid in {table}"),
                        });
                    }
                    tx.execute(&format!("UPDATE {table} SET uid='v1:uid:' || uid"), [])?;
                }
                tx.execute(
                    "UPDATE meta SET value=?1 WHERE key='schema_version'",
                    params![SCHEMA_VERSION.to_be_bytes().to_vec()],
                )?;
                tx.commit()?;
            }
            Some(_) => unreachable!("schema version bounded by the probe"),
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
        // The sequence cursor is validated like the lineage: a file that
        // lacks it (e.g. a torn pre-transaction init) faults every submit
        // forever — refuse instead.
        let next_seq: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key='next_seq'", [], |row| {
                row.get(0)
            })
            .map_err(|_| OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: {} has no sequence cursor",
                    path.display()
                ),
            })?;
        if blob_u64(next_seq).is_none() {
            return Err(OpenError {
                message: format!(
                    "STORE_RECOVERY_REQUIRED: {} has a corrupt sequence cursor",
                    path.display()
                ),
            });
        }
        // Seal every still-open accept-epoch in one transaction. The
        // RAM_ONLY dedup map is volatile by contract, so a restart cannot
        // distinguish a resubmitted RAM_ONLY key from a new one under a
        // still-open epoch — the review's double-send hole. Closing here
        // makes old keys fail closed: durable records keep resolving
        // Replay/get_by_key, everything else under the epoch gets
        // EPOCH_CLOSED, and the next open_epoch mints a fresh number.
        // An open epoch already present in closed_epoch is corruption —
        // the INSERT faults and open refuses rather than merging it.
        {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO closed_epoch(uid, network, epoch) SELECT uid, network, open_epoch FROM scope_epoch WHERE open_epoch IS NOT NULL",
                [],
            )?;
            tx.execute(
                "UPDATE scope_epoch SET open_epoch=NULL, open_ms=NULL WHERE open_epoch IS NOT NULL",
                [],
            )?;
            tx.commit()?;
        }
        // Crash recovery for DISPATCH_PREPARED records, split on the
        // persisted `submitted` claim flag: a record whose flag says the
        // SUBMIT may have left becomes INDETERMINATE (resolved by
        // QUERY_DISPATCH, never re-executed), while a record whose flag
        // says no USB write was ever claimed stays DISPATCH_PREPARED —
        // the dispatcher re-drives the same bound dispatch_seq, which the
        // device's replay rules make idempotent. An absent or undecodable
        // attachment cannot prove either side, so it is treated as
        // claimed. All other states reload untouched.
        let mut recovered = 0u64;
        {
            let mut stmt = conn.prepare(
                "SELECT seq, dispatch FROM operations WHERE dispatch_state='DISPATCH_PREPARED'",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (seq, blob) in rows {
                let claimed = blob
                    .as_deref()
                    .and_then(DispatchAttachment::decode)
                    .map_or(true, |att| att.submitted);
                if claimed {
                    conn.execute(
                        "UPDATE operations SET dispatch_state='INDETERMINATE' WHERE seq=?1",
                        params![seq],
                    )?;
                    recovered += 1;
                }
            }
        }
        if recovered > 0 {
            eprintln!("opstore: {recovered} prepared operation(s) recovered as INDETERMINATE");
        }
        // Rebuild lane positions a RAM_ONLY binding consumed before the
        // last shutdown (see `lane_tombstones` on the struct): every
        // dispatch_seq below `dispatch_next` under the still-bound lease
        // with no durable attachment is a hole. Positions further below
        // the allocator top than the device window were retired before
        // the crash — allocation never ran ahead of floor+window — so
        // only the top of the consumed range needs stand-ins.
        let mut lane_tombstones: HashMap<u64, StoredOperation> = HashMap::new();
        {
            let bound: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT value FROM meta WHERE key='dispatch_lease'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            let next: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT value FROM meta WHERE key='dispatch_next'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if let (Some(lease_raw), Some(next_raw)) = (bound, next) {
                if let (Ok(lease), Some(next_seq)) = (
                    <[u8; 16]>::try_from(lease_raw.as_slice()),
                    blob_u64(next_raw),
                ) {
                    let mut taken: HashSet<u64> = HashSet::new();
                    {
                        let mut stmt = conn.prepare(
                            "SELECT dispatch FROM operations WHERE dispatch IS NOT NULL",
                        )?;
                        let blobs = stmt
                            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                            .collect::<Result<Vec<_>, _>>()?;
                        for blob in blobs {
                            if let Some(att) = DispatchAttachment::decode(&blob) {
                                if att.lease == lease {
                                    taken.insert(att.dispatch_seq);
                                }
                            }
                        }
                    }
                    let low = next_seq.saturating_sub(1 + LANE_HOLE_WINDOW).max(1);
                    for dispatch_seq in low..next_seq {
                        if taken.contains(&dispatch_seq) {
                            continue;
                        }
                        let mut dispatch = DispatchAttachment::fresh(lease, lineage, dispatch_seq);
                        // The volatile claim is unknowable — assume the
                        // SUBMIT may have left and let QUERY resolve the
                        // position (NotRetained proves it a hole to SKIP).
                        dispatch.submitted = true;
                        let op_seq = u64::MAX - dispatch_seq;
                        lane_tombstones.insert(
                            op_seq,
                            StoredOperation {
                                seq: op_seq,
                                principal: Principal::UnixUid(0),
                                network: 0,
                                epoch: 0,
                                key: [0; 16],
                                dest_kind: 0,
                                dest: 0,
                                delivery: 0,
                                priority: 0,
                                ttl_ms: 0,
                                storage: crate::canonical::STORAGE_RAM,
                                hop_limit: 0,
                                payload: Vec::new(),
                                canonical: Vec::new(),
                                hash: [0; 32],
                                accepted_ms: 0,
                                accepted_mono_ms: 0,
                                dispatch_state: DispatchState::Indeterminate,
                                terminal_ms: Some(0),
                                dispatch: Some(dispatch),
                            },
                        );
                    }
                }
            }
        }
        // Final sweep now that WAL recovery and the writes above have
        // materialized every sidecar: main file, -wal, -shm and -journal
        // all owner-only. This is the regression-proof layer — even if
        // the mode-inheritance assumption above ever stopped holding,
        // a file left group/other-readable here refuses startup.
        enforce_owner_only(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            lineage,
            created_fresh: fresh,
            conn,
            ram_by_identity: HashMap::new(),
            ram_by_seq: HashMap::new(),
            lane_tombstones,
            mono_anchor: HashMap::new(),
        })
    }

    /// True only when `open` created the store file — i.e. this boot
    /// minted a brand-new lineage rather than resuming one on disk.
    /// A fresh lineage invalidates every gateway dispatch lane bound
    /// under a previous store until the device reboots.
    pub fn was_created_fresh(&self) -> bool {
        self.created_fresh
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

    /// Per-lease dispatch_seq allocator, persisted in meta so a daemon
    /// restart resumes the lane's numbering instead of re-issuing a seq the
    /// device may still hold. A different lease rebinds the lane and
    /// restarts numbering at 1 — matching the device's fresh window.
    fn dispatch_next_tx(tx: &Transaction<'_>, lease: [u8; 16]) -> Result<u64, rusqlite::Error> {
        let bound: Option<Vec<u8>> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='dispatch_lease'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let next = if bound.as_deref() == Some(&lease[..]) {
            let raw: Vec<u8> = tx.query_row(
                "SELECT value FROM meta WHERE key='dispatch_next'",
                [],
                |row| row.get(0),
            )?;
            blob_u64(raw).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    "dispatch_next".into(),
                )
            })?
        } else {
            1
        };
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('dispatch_lease', ?1)",
            params![lease.to_vec()],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('dispatch_next', ?1)",
            params![u64_blob(next.saturating_add(1).max(1))],
        )?;
        Ok(next)
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
        scope: &EpochScope,
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
            // Eligible when every record concluded and its protection
            // lapsed: `terminal_ms` is set on every terminal transition and
            // on resolved device-terminal outcomes with no terminal
            // vocabulary name (a completed BEST_EFFORT keeps
            // GATEWAY_ACCEPTED), so `terminal_ms IS NOT NULL` is the
            // concluded test — never a state-name list alone.
            let mut eligible = true;
            {
                let mut stmt = tx.prepare(
                    "SELECT terminal_ms FROM operations WHERE uid=?1 AND network=?2 AND epoch=?3",
                )?;
                let rows = stmt.query_map(
                    params![uid.storage_key(), *network as i64, u64_blob(candidate)],
                    |row| row.get::<_, Option<i64>>(0),
                )?;
                for row in rows {
                    let lapsed = row?
                        .and_then(db_to_ms)
                        .is_some_and(|t| t.saturating_add(RETENTION_MS) <= now_ms);
                    if !lapsed {
                        eligible = false;
                        break;
                    }
                }
            }
            if eligible {
                eligible = ram_by_identity
                    .values()
                    .filter(|op| {
                        op.principal == *uid && op.network == *network && op.epoch == candidate
                    })
                    .all(|op| {
                        op.concluded()
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
                params![uid.storage_key(), *network as i64, u64_blob(floor)],
            )?;
            tx.execute(
                "DELETE FROM closed_epoch WHERE uid=?1 AND network=?2 AND epoch=?3",
                params![uid.storage_key(), *network as i64, u64_blob(candidate)],
            )?;
            tx.execute(
                "DELETE FROM operations WHERE uid=?1 AND network=?2 AND epoch=?3",
                params![uid.storage_key(), *network as i64, u64_blob(candidate)],
            )?;
            delta.retired.extend(
                ram_by_identity
                    .keys()
                    .filter(|id| {
                        id.principal == *uid && id.network == *network && id.epoch == candidate
                    })
                    .cloned(),
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
            ram_by_seq.insert(op.seq, identity.clone());
            ram_by_identity.insert(identity, op);
        }
    }

    fn submit_tx(
        ram_by_identity: &HashMap<OpIdentity, StoredOperation>,
        delta: &mut RamDelta,
        tx: &Transaction<'_>,
        path: &Path,
        principal: &Principal,
        req: &SendRequest,
        // Wall and monotonic admit stamps travel together: the record's
        // TTL runs on `now_ms`, the rewind-proof budget on `mono_ms`.
        stamps: (u64, u64),
    ) -> Result<SubmitOutcome, rusqlite::Error> {
        let (now_ms, mono_ms) = stamps;
        let identity = OpIdentity {
            principal: principal.clone(),
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
                    principal.storage_key(),
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
        let scope = (principal.clone(), req.network);
        Self::retire_tx(ram_by_identity, delta, tx, &scope, now_ms)?;
        match read_scope(tx, &scope)? {
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
            Some(_) if closed_contains(tx, &scope, req.epoch)? => {
                return Ok(SubmitOutcome::EpochClosed)
            }
            _ => return Ok(SubmitOutcome::UnknownEpoch),
        }
        // Physical budget, checked here and not before the transaction:
        // dedup (Replay/Conflict above) must resolve even under
        // exhaustion — the contract orders identity before quota — and an
        // unmeasurable store file means the daemon cannot vouch for
        // durability at all.
        match store_file_bytes(path) {
            Some(used) if used < STORE_BYTES_CAP => {}
            Some(_) => return Ok(SubmitOutcome::NoCapacity),
            None => {
                eprintln!(
                    "opstore fault: store file {} is unmeasurable",
                    path.display()
                );
                return Ok(SubmitOutcome::StoreFault);
            }
        }
        let records: i64 = tx.query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        let total_records = records as usize + ram_by_identity.len();
        // An in-flight state only counts while the record is unresolved —
        // a concluded device-terminal outcome (terminal_ms set) frees its
        // active slot even though the vocabulary has no terminal name for
        // a completed BEST_EFFORT.
        let active: i64 = tx.query_row(
            &format!("SELECT COUNT(*) FROM operations WHERE dispatch_state IN ({ACTIVE_SQL}) AND terminal_ms IS NULL"),
            [],
            |row| row.get(0),
        )?;
        let mut total_active = active as usize;
        let mut principal_active = 0;
        for op in ram_by_identity.values() {
            if op.dispatch_state.is_active() && !op.concluded() {
                total_active += 1;
                if &op.principal == principal {
                    principal_active += 1;
                }
            }
        }
        if total_records >= RECORD_CAP || total_active >= ACTIVE_CAP {
            return Ok(SubmitOutcome::NoCapacity);
        }
        let durable_principal: i64 = tx.query_row(
            &format!(
                "SELECT COUNT(*) FROM operations WHERE uid=?1 AND dispatch_state IN ({ACTIVE_SQL}) AND terminal_ms IS NULL"
            ),
            params![principal.storage_key()],
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
            principal: principal.clone(),
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
            accepted_mono_ms: mono_ms,
            dispatch_state: DispatchState::HostQueued,
            terminal_ms: None,
            dispatch: None,
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
                    principal.storage_key(),
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
        if let Some(identity) = self.ram_by_seq.get(&seq).cloned() {
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
    pub fn retire_for_test(&mut self, scope: (u32, u64), now_ms: u64) -> u64 {
        let scope = (Principal::UnixUid(scope.0), scope.1);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("retire txn");
        let mut delta = RamDelta::default();
        Self::retire_tx(&self.ram_by_identity, &mut delta, &tx, &scope, now_ms).expect("retire");
        let floor = read_scope(&tx, &scope)
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
    pub fn veto_next_commit(&self) {
        let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.conn.commit_hook(Some(move || {
            armed.swap(false, std::sync::atomic::Ordering::Relaxed)
        }));
    }

    fn open_epoch_tx(
        ram_by_identity: &HashMap<OpIdentity, StoredOperation>,
        delta: &mut RamDelta,
        tx: &Transaction<'_>,
        scope: &EpochScope,
        now_ms: u64,
    ) -> Result<Result<(u64, bool), OpenEpochError>, rusqlite::Error> {
        let (uid, network) = scope;
        if read_scope(tx, scope)?.is_none() {
            tx.execute(
                "INSERT INTO scope_epoch(uid, network, floor, next_epoch, open_epoch, open_ms) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    uid.storage_key(),
                    *network as i64,
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
                params![uid.storage_key(), *network as i64, u64_blob(open)],
            )?;
            tx.execute(
                "UPDATE scope_epoch SET open_epoch=NULL, open_ms=NULL WHERE uid=?1 AND network=?2",
                params![uid.storage_key(), *network as i64],
            )?;
        }
        if unretired_count(tx, scope)? >= MAX_UNRETIRED_EPOCHS || row.next_epoch == u64::MAX {
            return Ok(Err(OpenEpochError::NoCapacity));
        }
        let epoch = row.next_epoch;
        tx.execute(
            "UPDATE scope_epoch SET next_epoch=?3, open_epoch=?4, open_ms=?5 WHERE uid=?1 AND network=?2",
            params![
                uid.storage_key(),
                *network as i64,
                u64_blob(epoch.saturating_add(1)),
                u64_blob(epoch),
                ms_to_db(now_ms),
            ],
        )?;
        Ok(Ok((epoch, true)))
    }

    /// Merge the volatile monotonic admit stamp back into a row-read
    /// record: the DB column layout predates the anchor and a monotonic
    /// stamp is meaningless after a restart anyway.
    fn with_mono_anchor(&self, mut op: StoredOperation) -> StoredOperation {
        if op.accepted_mono_ms == 0 {
            if let Some(mono) = self.mono_anchor.get(&op.seq) {
                op.accepted_mono_ms = *mono;
            }
        }
        op
    }

    /// Lane allocator for the RAM-overlay branch of prepare_dispatch — the
    /// meta keys live in the durable file even though the record does not,
    /// so a restart still resumes the same lease's numbering.
    fn alloc_lane_seq(conn: &mut Connection, lease: [u8; 16]) -> Result<u64, ()> {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| eprintln!("opstore fault: {error}"))?;
        let next = Self::dispatch_next_tx(&tx, lease)
            .map_err(|error| eprintln!("opstore fault: {error}"))?;
        if next == 0 || next == u64::MAX {
            eprintln!("opstore fault: dispatch sequence allocator exhausted");
            return Err(());
        }
        tx.commit()
            .map_err(|error| eprintln!("opstore fault: {error}"))?;
        Ok(next)
    }

    /// Config SingleAuthority ledger (scope-gateway-config P5): reserve the
    /// next `authority_sequence` for this issuance identity in one
    /// immediate transaction, so a crash leaves a gap, never a reuse.
    /// The issuance identity (network, authority, generation) pins on
    /// first use — a pre-outbox database migrates by pinning whatever
    /// identity issues next (and keeps its surviving `config_auth_seq`
    /// cursor), while a changed identity is refused until the operator
    /// reprovisions the store lineage for the rotation.
    pub fn issue_reserve_tx(&mut self, identity: &IssueIdentity) -> Result<u64, IssueRefusal> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        let identity_blob =
            issue_identity_blob(identity.network, identity.authority, identity.generation);
        let pinned: Option<Vec<u8>> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='config_auth_identity'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        match pinned {
            Some(pinned) if pinned != identity_blob => {
                eprintln!("opstore fault: config issuance identity changed; reprovision the op-store to rotate");
                return Err(IssueRefusal::IdentityChanged);
            }
            Some(_) => {}
            None => {
                tx.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('config_auth_identity', ?1)",
                    params![identity_blob],
                )
                .map_err(|error| {
                    eprintln!("opstore fault: {error}");
                    IssueRefusal::Unprovable
                })?;
            }
        }
        let prior: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT kind, sequence FROM config_outbox WHERE opid=?1",
                params![identity.op_id.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        if let Some((kind, sequence)) = prior {
            if kind != i64::from(identity.kind) {
                return Err(IssueRefusal::OpConflict);
            }
            let sequence = blob_u64(sequence).ok_or_else(|| {
                eprintln!("opstore fault: corrupt config outbox sequence");
                IssueRefusal::Unprovable
            })?;
            tx.commit().map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
            return Ok(sequence);
        }
        // Smallest allocator state first: the sequence cursor survives from
        // before the outbox existed, so a migrated database keeps numbering.
        let raw: Option<Vec<u8>> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='config_auth_seq'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        let next = match raw {
            Some(raw) => blob_u64(raw).ok_or_else(|| {
                eprintln!("opstore fault: corrupt config_auth_seq cursor");
                IssueRefusal::Unprovable
            })?,
            None => 1,
        };
        if next == 0 || next == u64::MAX {
            eprintln!("opstore fault: config authority sequence exhausted");
            return Err(IssueRefusal::Unprovable);
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM config_outbox", [], |row| row.get(0))
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        if count >= ISSUE_OUTBOX_CAP as i64 {
            let completed: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT opid FROM config_outbox WHERE terminal=1 ORDER BY rowid ASC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    eprintln!("opstore fault: {error}");
                    IssueRefusal::Unprovable
                })?;
            let Some(completed) = completed else {
                return Err(IssueRefusal::Capacity);
            };
            tx.execute(
                "DELETE FROM config_outbox WHERE opid=?1",
                params![completed],
            )
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('config_auth_seq', ?1)",
            params![u64_blob(next + 1)],
        )
        .map_err(|error| {
            eprintln!("opstore fault: {error}");
            IssueRefusal::Unprovable
        })?;
        tx.execute(
            "INSERT INTO config_outbox(opid, kind, target, ns, profile, authority, \
             generation, network, sequence, canonical, signed) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
            params![
                identity.op_id.to_vec(),
                identity.kind as i64,
                u64_blob(identity.target),
                identity.namespace as i64,
                identity.profile as i64,
                u64_blob(identity.authority),
                identity.generation as i64,
                u64_blob(identity.network),
                u64_blob(next),
            ],
        )
        .map_err(|error| {
            eprintln!("opstore fault: {error}");
            IssueRefusal::Unprovable
        })?;
        tx.commit().map_err(|error| {
            eprintln!("opstore fault: {error}");
            IssueRefusal::Unprovable
        })?;
        // Read the reservation back: the sequence the lane signs under
        // must be the one the store actually holds.
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sequence FROM config_outbox WHERE opid=?1",
                params![identity.op_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        match stored.and_then(blob_u64) {
            Some(stored) if stored == next => Ok(next),
            _ => {
                eprintln!("opstore fault: config outbox reserve readback mismatch");
                Err(IssueRefusal::Unprovable)
            }
        }
    }

    /// Bind the finalized canonical to the reservation, then read it back.
    /// Same op_id + same bytes is idempotent; different bytes conflict.
    pub fn issue_bind_tx(
        &mut self,
        op_id: &[u8; 16],
        canonical: &[u8],
    ) -> Result<(), IssueRefusal> {
        let stored: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT canonical FROM config_outbox WHERE opid=?1",
                params![op_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        match stored {
            None => Err(IssueRefusal::Unprovable),
            Some(Some(stored)) if stored != canonical => Err(IssueRefusal::OpConflict),
            Some(Some(_)) => Ok(()),
            Some(None) => {
                self.conn
                    .execute(
                        "UPDATE config_outbox SET canonical=?1 WHERE opid=?2",
                        params![canonical.to_vec(), op_id.to_vec()],
                    )
                    .map_err(|error| {
                        eprintln!("opstore fault: {error}");
                        IssueRefusal::Unprovable
                    })?;
                let readback: Option<Vec<u8>> = self
                    .conn
                    .query_row(
                        "SELECT canonical FROM config_outbox WHERE opid=?1",
                        params![op_id.to_vec()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| {
                        eprintln!("opstore fault: {error}");
                        IssueRefusal::Unprovable
                    })?
                    .flatten();
                if readback.as_deref() == Some(canonical) {
                    Ok(())
                } else {
                    eprintln!("opstore fault: config outbox bind readback mismatch");
                    Err(IssueRefusal::Unprovable)
                }
            }
        }
    }

    /// Store the signed original, then read it back — the lane may only
    /// transmit bytes the store proved it holds. Needs a bound canonical.
    pub fn issue_signed_tx(&mut self, op_id: &[u8; 16], signed: &[u8]) -> Result<(), IssueRefusal> {
        let stored: Option<OutboxHalves> = self
            .conn
            .query_row(
                "SELECT canonical, signed FROM config_outbox WHERE opid=?1",
                params![op_id.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        let (canonical, stored) = match stored {
            None => return Err(IssueRefusal::Unprovable),
            Some(row) => row,
        };
        if canonical.is_none() {
            return Err(IssueRefusal::Unprovable);
        }
        match stored {
            Some(stored) if stored != signed => Err(IssueRefusal::OpConflict),
            Some(_) => Ok(()),
            None => {
                self.conn
                    .execute(
                        "UPDATE config_outbox SET signed=?1 WHERE opid=?2",
                        params![signed.to_vec(), op_id.to_vec()],
                    )
                    .map_err(|error| {
                        eprintln!("opstore fault: {error}");
                        IssueRefusal::Unprovable
                    })?;
                let readback: Option<Vec<u8>> = self
                    .conn
                    .query_row(
                        "SELECT signed FROM config_outbox WHERE opid=?1",
                        params![op_id.to_vec()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| {
                        eprintln!("opstore fault: {error}");
                        IssueRefusal::Unprovable
                    })?
                    .flatten();
                if readback.as_deref() == Some(signed) {
                    Ok(())
                } else {
                    eprintln!("opstore fault: config outbox signed readback mismatch");
                    Err(IssueRefusal::Unprovable)
                }
            }
        }
    }

    /// Load the (canonical, signed) original, retransmit-only. None until
    /// both halves are stored.
    pub fn issue_original_row(&mut self, op_id: &[u8; 16]) -> Option<(Vec<u8>, Vec<u8>)> {
        let row: Option<OutboxHalves> = self
            .conn
            .query_row(
                "SELECT canonical, signed FROM config_outbox WHERE opid=?1",
                params![op_id.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .ok()?;
        let (canonical, signed) = row?;
        match (canonical, signed) {
            (Some(canonical), Some(signed)) => Some((canonical, signed)),
            _ => None,
        }
    }

    pub fn issue_complete_tx(&mut self, op_id: &[u8; 16]) -> Result<(), IssueRefusal> {
        let updated = self
            .conn
            .execute(
                "UPDATE config_outbox SET terminal=1 WHERE opid=?1 AND signed IS NOT NULL",
                params![op_id.to_vec()],
            )
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        if updated != 1 {
            return Err(IssueRefusal::Unprovable);
        }
        let terminal: i64 = self
            .conn
            .query_row(
                "SELECT terminal FROM config_outbox WHERE opid=?1",
                params![op_id.to_vec()],
                |row| row.get(0),
            )
            .map_err(|error| {
                eprintln!("opstore fault: {error}");
                IssueRefusal::Unprovable
            })?;
        if terminal == 1 {
            Ok(())
        } else {
            Err(IssueRefusal::Unprovable)
        }
    }
}

/// The two nullable outbox halves (canonical, signed) as one row read.
type OutboxHalves = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The pinned issuance identity: network u64 || authority u64 ||
/// generation u32 (20 bytes, big-endian).
fn issue_identity_blob(network: u64, authority: u64, generation: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&network.to_be_bytes());
    out.extend_from_slice(&authority.to_be_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out
}

impl OperationStore for SqliteOperationStore {
    fn lineage(&self) -> [u8; 16] {
        self.lineage
    }

    fn durable(&self) -> bool {
        true
    }

    fn open_epoch_principal(
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
        let outcome = match Self::open_epoch_tx(ram_by_identity, &mut delta, &tx, &scope, now_ms) {
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

    fn submit_at_principal(
        &mut self,
        principal: &Principal,
        req: &SendRequest,
        now_ms: u64,
        mono_ms: u64,
    ) -> SubmitOutcome {
        let Self {
            conn,
            ram_by_identity,
            ram_by_seq,
            path,
            mono_anchor,
            ..
        } = self;
        let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(error) => return Self::fault(error),
        };
        let mut delta = RamDelta::default();
        let outcome = match Self::submit_tx(
            ram_by_identity,
            &mut delta,
            &tx,
            path.as_path(),
            principal,
            req,
            (now_ms, mono_ms),
        ) {
            Ok(outcome) => outcome,
            Err(error) => return Self::fault(error),
        };
        match tx.commit() {
            Ok(()) => {
                Self::apply_ram_delta(ram_by_identity, ram_by_seq, delta);
                // Volatile monotonic admit stamp (see the field): only
                // recorded once the record itself committed.
                if let SubmitOutcome::Accepted { seq } = outcome {
                    if mono_ms != 0 {
                        mono_anchor.insert(seq, mono_ms);
                    }
                }
                outcome
            }
            Err(error) => Self::fault(error),
        }
    }

    fn get_by_seq(&self, seq: u64) -> Result<Option<StoredOperation>, ()> {
        if let Some(identity) = self.ram_by_seq.get(&seq) {
            return Ok(self.ram_by_identity.get(identity).cloned());
        }
        if let Some(op) = self.lane_tombstones.get(&seq) {
            return Ok(Some(op.clone()));
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
            .map(|op| op.map(|op| self.with_mono_anchor(op)))
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
                    identity.principal.storage_key(),
                    identity.network as i64,
                    u64_blob(identity.epoch),
                    identity.key.to_vec(),
                ],
                read_operation_row,
            )
            .optional()
            .map(|op| op.map(|op| self.with_mono_anchor(op)))
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

    fn dispatch_view(&self) -> Result<Vec<StoredOperation>, ()> {
        let failed = |error: rusqlite::Error| {
            eprintln!("opstore fault: {error}");
        };
        let mut out: Vec<StoredOperation> = self
            .ram_by_identity
            .values()
            .filter(|op| !op.concluded() || op.dispatch.is_some())
            .cloned()
            .collect();
        // Live records plus every record still carrying a dispatch
        // attachment (needed to drive the device retire floor).
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {OPERATION_COLUMNS} FROM operations WHERE dispatch IS NOT NULL OR (terminal_ms IS NULL AND dispatch_state NOT IN ({TERMINAL_SQL}))"
            ))
            .map_err(failed)?;
        let rows = stmt.query_map([], read_operation_row).map_err(failed)?;
        for row in rows {
            out.push(self.with_mono_anchor(row.map_err(failed)?));
        }
        // Lane tombstones carry attachments too — the dispatcher resolves
        // them through the same query/skip/retire passes.
        out.extend(self.lane_tombstones.values().cloned());
        Ok(out)
    }

    fn prepare_dispatch(
        &mut self,
        op_seq: u64,
        lease: [u8; 16],
        dispatcher: [u8; 16],
    ) -> Result<PrepareOutcome, ()> {
        // RAM-overlay records are volatile by contract; mutate in place.
        if let Some(identity) = self.ram_by_seq.get(&op_seq).cloned() {
            let Some(op) = self.ram_by_identity.get_mut(&identity) else {
                return Ok(PrepareOutcome::NotFound);
            };
            if op.dispatch_state != DispatchState::HostQueued || op.dispatch.is_some() {
                return Ok(PrepareOutcome::NotQueued(op.dispatch_state));
            }
            // The overlay uses the durable allocator too: sequence numbers
            // must never repeat within a lease regardless of storage class.
            let dispatch_seq = Self::alloc_lane_seq(&mut self.conn, lease)?;
            let attachment = DispatchAttachment::fresh(lease, dispatcher, dispatch_seq);
            op.dispatch = Some(attachment.clone());
            op.dispatch_state = DispatchState::DispatchPrepared;
            return Ok(PrepareOutcome::Prepared(attachment));
        }
        if op_seq > i64::MAX as u64 {
            return Ok(PrepareOutcome::NotFound);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| eprintln!("opstore fault: {error}"))?;
        let outcome = (|| -> Result<Option<PrepareOutcome>, rusqlite::Error> {
            let Some(op) = tx
                .query_row(
                    &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE seq=?1"),
                    params![op_seq as i64],
                    read_operation_row,
                )
                .optional()?
            else {
                return Ok(Some(PrepareOutcome::NotFound));
            };
            if op.dispatch_state != DispatchState::HostQueued || op.dispatch.is_some() {
                return Ok(Some(PrepareOutcome::NotQueued(op.dispatch_state)));
            }
            let dispatch_seq = Self::dispatch_next_tx(&tx, lease)?;
            if dispatch_seq == 0 || dispatch_seq == u64::MAX {
                // Reserved position — never issue it.
                return Ok(None);
            }
            let attachment = DispatchAttachment::fresh(lease, dispatcher, dispatch_seq);
            // DISPATCH_PREPARED and its identity commit together, before
            // any USB write can be claimed for this dispatch_seq.
            tx.execute(
                "UPDATE operations SET dispatch_state='DISPATCH_PREPARED', dispatch=?1 WHERE seq=?2",
                params![attachment.encode(), op.seq as i64],
            )?;
            Ok(Some(PrepareOutcome::Prepared(attachment)))
        })();
        match outcome {
            Ok(Some(outcome)) => {
                tx.commit()
                    .map_err(|error| eprintln!("opstore fault: {error}"))?;
                Ok(outcome)
            }
            Ok(None) => {
                eprintln!("opstore fault: dispatch sequence allocator exhausted");
                Err(())
            }
            Err(error) => {
                eprintln!("opstore fault: {error}");
                Err(())
            }
        }
    }

    fn update_operation(
        &mut self,
        op_seq: u64,
        mutate: &mut dyn FnMut(&mut StoredOperation) -> bool,
    ) -> Result<bool, ()> {
        if let Some(identity) = self.ram_by_seq.get(&op_seq).cloned() {
            // Same veto rule as the durable path: snapshot so a false
            // return leaves no partial mutation committed.
            let Some(op) = self.ram_by_identity.get_mut(&identity) else {
                return Ok(false);
            };
            let before = op.clone();
            return Ok(if mutate(op) {
                true
            } else {
                *op = before;
                false
            });
        }
        if let Some(op) = self.lane_tombstones.get_mut(&op_seq) {
            let before = op.clone();
            return Ok(if mutate(op) {
                true
            } else {
                *op = before;
                false
            });
        }
        if op_seq > i64::MAX as u64 {
            return Ok(false);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| eprintln!("opstore fault: {error}"))?;
        let applied = (|| -> Result<Option<bool>, rusqlite::Error> {
            let Some(mut op) = tx
                .query_row(
                    &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE seq=?1"),
                    params![op_seq as i64],
                    read_operation_row,
                )
                .optional()?
            else {
                return Ok(None);
            };
            if !mutate(&mut op) {
                return Ok(Some(false));
            }
            tx.execute(
                "UPDATE operations SET dispatch_state=?1, terminal_ms=?2, dispatch=?3 WHERE seq=?4",
                params![
                    op.dispatch_state.name(),
                    op.terminal_ms.map(ms_to_db),
                    op.dispatch.as_ref().map(DispatchAttachment::encode),
                    op.seq as i64,
                ],
            )?;
            Ok(Some(true))
        })();
        match applied {
            Ok(Some(true)) => {
                tx.commit()
                    .map_err(|error| eprintln!("opstore fault: {error}"))?;
                Ok(true)
            }
            // Missing record or vetoed mutation: nothing committed.
            Ok(_) => Ok(false),
            Err(error) => {
                eprintln!("opstore fault: {error}");
                Err(())
            }
        }
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
                "SELECT MIN(terminal_ms) FROM operations WHERE terminal_ms IS NOT NULL AND terminal_ms > ?1",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(failed)?;
    let mut lapse = durable_lapse
        .and_then(db_to_ms)
        .map(|t| t.saturating_add(RETENTION_MS));
    for op in ram.values() {
        if !op.concluded() {
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
            let dir = std::env::temp_dir().join(format!(
                "routeloom-cap1-{}-{}-{id}",
                std::process::id(),
                name
            ));
            let _ = std::fs::remove_dir_all(&dir);
            routeloom_peercred::create_private_dir_all(&dir).unwrap();
            let path = dir.join("ops.db");
            Self::remove(&path);
            Self { path }
        }

        fn remove(path: &Path) {
            let _ = std::fs::remove_file(path);
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let _ = std::fs::remove_file(sidecar);
            }
        }

        fn open(&self) -> SqliteOperationStore {
            SqliteOperationStore::open(&self.path).expect("open test store")
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            Self::remove(&self.path);
            let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
        }
    }

    fn request(key: &str, epoch: u64, storage: &str) -> SendRequest {
        let json = format!(
            "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch:016x}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{{\"storage\":\"{storage}\"}}}}"
        );
        let mut req = parse_submit(&routeloom_json::parse(&json).unwrap(), None).unwrap();
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

    #[test]
    fn device_outcome_survives_reopen() {
        let db = TestDb::new("device-outcome");
        let key = "00112233445566778899aabbccddeeff";
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            let seq = submit(&mut store, 501, &durable(key, 1), 1000);
            match store.prepare_dispatch(seq, [7; 16], [8; 16]) {
                Ok(PrepareOutcome::Prepared(_)) => {}
                _ => panic!("expected prepare"),
            }
            store
                .update_operation(seq, &mut |op| {
                    let d = op.dispatch.as_mut().unwrap();
                    d.msg_session = Some(5);
                    d.msg_seq = Some(900);
                    true
                })
                .unwrap();
            let mut operation_id = [8_u8; 24];
            operation_id[16..].copy_from_slice(&seq.to_be_bytes());
            assert!(store
                .attach_device_outcome(&operation_id, 5, 900, "failed", Some("NO_ROUTE"))
                .unwrap());
        }
        let store = db.open();
        let identity = OpIdentity {
            principal: Principal::UnixUid(501),
            network: 1,
            epoch: 1,
            key: durable(key, 1).key,
        };
        let op = store.get_by_key(&identity).unwrap().unwrap();
        let dispatch = op.dispatch.as_ref().unwrap();
        assert_eq!(dispatch.device_state.as_deref(), Some("failed"));
        assert_eq!(dispatch.device_reason.as_deref(), Some("NO_ROUTE"));
    }

    #[test]
    fn sid_epoch_and_operation_survive_restart_without_uid_alias() {
        let db = TestDb::new("sid-principal");
        let sid = Principal::WindowsSid("S-1-5-21-100-200-300-501".into());
        let unix = Principal::UnixUid(501);
        let req = durable("00112233445566778899aabbccddeeff", 1);
        let sid_seq;
        {
            let mut store = db.open();
            assert_eq!(
                store.open_epoch_principal((sid.clone(), 1), 0),
                Ok((1, true))
            );
            assert_eq!(
                store.open_epoch_principal((unix.clone(), 1), 0),
                Ok((1, true))
            );
            sid_seq = match store.submit_at_principal(&sid, &req, 1000, 0) {
                SubmitOutcome::Accepted { seq } => seq,
                other => panic!("SID admission: {}", outcome_name(&other)),
            };
            assert!(matches!(
                store.submit_at_principal(&unix, &req, 1000, 0),
                SubmitOutcome::Accepted { .. }
            ));
        }
        let mut store = db.open();
        let identity = OpIdentity {
            principal: sid.clone(),
            network: 1,
            epoch: 1,
            key: req.key,
        };
        assert_eq!(store.get_by_key(&identity).unwrap().unwrap().seq, sid_seq);
        assert_eq!(store.get_by_seq(sid_seq).unwrap().unwrap().principal, sid);
        assert!(
            matches!(store.submit_at_principal(&unix, &req, 2000, 0), SubmitOutcome::Replay { seq } if seq != sid_seq)
        );
        assert!(
            matches!(store.submit_at_principal(&identity.principal, &req, 2000, 0), SubmitOutcome::Replay { seq } if seq == sid_seq)
        );
    }

    #[cfg(windows)]
    #[test]
    fn existing_operation_db_requires_owner_dacl() {
        let db = TestDb::new("dacl");
        // A normal create inherits directory grants and is not an explicit
        // protected owner-only file, even inside a private directory.
        std::fs::write(&db.path, []).unwrap();
        let error = SqliteOperationStore::open(&db.path).unwrap_err();
        assert!(error.message.contains("not private"), "{error}");
    }

    #[test]
    fn schema_three_uid_fixture_migrates_to_versioned_principal() {
        let db = TestDb::new("uid-v3");
        let req = durable("00112233445566778899aabbccddeeff", 1);
        {
            let conn = Connection::open(&db.path).unwrap();
            conn.execute_batch(&SCHEMA_SQL.replace("uid TEXT", "uid INTEGER"))
                .unwrap();
            conn.execute_batch(CONFIG_OUTBOX_SQL).unwrap();
            for (key, value) in [
                ("schema_version", 3u32.to_be_bytes().to_vec()),
                ("lineage", vec![1; 16]),
                ("next_seq", u64_blob(2)),
            ] {
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES (?1,?2)",
                    params![key, value],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO scope_epoch(uid,network,floor,next_epoch,open_epoch,open_ms) VALUES (501,1,?1,?2,?3,0)",
                params![u64_blob(0), u64_blob(2), u64_blob(1)],
            ).unwrap();
            conn.execute(
                "INSERT INTO operations(seq,uid,network,epoch,key,dest_kind,dest,delivery,priority,ttl_ms,storage,hop_limit,payload,canonical,hash,accepted_ms,dispatch_state,terminal_ms) VALUES (1,501,1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,1000,'HOST_QUEUED',NULL)",
                params![u64_blob(1), req.key.to_vec(), req.dest_kind, u64_blob(req.dest), req.delivery, req.priority, req.ttl_ms, req.storage, req.hop_limit, req.payload, req.canonical, req.hash.to_vec()],
            ).unwrap();
        }
        let mut store = db.open();
        let op = store.get_by_seq(1).unwrap().unwrap();
        assert_eq!(op.principal, Principal::UnixUid(501));
        assert!(matches!(
            store.submit_at_principal(&Principal::UnixUid(501), &req, 2000, 0),
            SubmitOutcome::Replay { seq: 1 }
        ));
        let version: Vec<u8> = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_be_bytes());
        let key: String = store
            .conn
            .query_row("SELECT uid FROM operations WHERE seq=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(key, "v1:uid:501");
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
            // The restart sealed epoch 1 — the RAM dedup map is gone, so
            // the store cannot re-admit under it safely. open_epoch mints
            // a fresh number instead of rebinding.
            assert_eq!(store.open_epoch((501, 1), 100), Ok((2, true)));
            // Durable record intact, byte for byte.
            let op = store.get_by_seq(1).unwrap().unwrap();
            assert_eq!(op.payload, vec![0x00, 0xff]);
            assert_eq!(op.accepted_ms, 1000);
            assert_eq!(op.dispatch_state, DispatchState::HostQueued);
            let identity = OpIdentity {
                principal: Principal::UnixUid(501),
                network: 1,
                epoch: 1,
                key: durable("00112233445566778899aabbccddeeff", 1).key,
            };
            assert_eq!(store.get_by_key(&identity).unwrap().unwrap().seq, 1);
            // Replay after restart returns the same id, not a new record —
            // durable dedup resolves before the epoch check.
            match store.submit(501, &durable("00112233445566778899aabbccddeeff", 1), 2000) {
                SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
                other => panic!("expected replay, got {}", outcome_name(&other)),
            }
            // RAM_ONLY record is gone — and its sequence is not reused.
            assert!(store.get_by_seq(2).unwrap().is_none());
            let seq = submit(
                &mut store,
                501,
                &durable("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2),
                2000,
            );
            assert_eq!(seq, 3);
        }
    }

    /// `was_created_fresh` is the lineage-loss signal: a store that
    /// minted its file this open reports it so the caller can warn about
    /// orphaned gateway lanes; reopening the same file reports false —
    /// the lineage survived and no lane moved.
    #[test]
    fn was_created_fresh_only_on_first_open() {
        let db = TestDb::new("created-fresh");
        {
            let store = db.open();
            assert!(store.was_created_fresh());
        }
        {
            let store = db.open();
            assert!(!store.was_created_fresh());
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
            // The restart sealed the still-open epoch 2 alongside the
            // already-closed 1 — no rotation is replayed and the next
            // open_epoch mints a fresh number.
            assert_eq!(
                store.open_epoch((501, 1), EPOCH_WINDOW_MS + 1),
                Ok((3, true))
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
                "INSERT INTO operations(seq, uid, network, epoch, key, dest_kind, dest, delivery, priority, ttl_ms, storage, hop_limit, payload, canonical, hash, accepted_ms, dispatch_state, terminal_ms) VALUES (99,'v1:uid:501',1,?1,?2,0,?3,1,1,5000,1,10,x'00',x'00',?4,0,'HOST_QUEUED',NULL)",
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
                    "INSERT INTO operations(seq, uid, network, epoch, key, dest_kind, dest, delivery, priority, ttl_ms, storage, hop_limit, payload, canonical, hash, accepted_ms, dispatch_state, terminal_ms) VALUES (?1,'v1:uid:501',1,?2,?3,0,?4,1,1,5000,1,10,x'',x'',?5,0,'HOST_QUEUED',NULL)",
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
        // A stray rollback-journal sidecar counts too.
        std::fs::write(dir.join("store.db-journal"), vec![0u8; 5]).unwrap();
        assert_eq!(store_file_bytes(&main), Some(137));
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
        assert_eq!(
            store.get_by_seq(ram_seq).unwrap().unwrap().principal,
            Principal::UnixUid(501)
        );
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
            principal: Principal::UnixUid(501),
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
            principal: Principal::UnixUid(501),
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

    /// Reopen drives REAL attachments through the recovery split: a
    /// claimed (submitted) record lands INDETERMINATE, a never-claimed
    /// one stays re-drivable, a RAM binding leaves a payload-free lane
    /// tombstone, and the per-lease allocator resumes its numbering.
    #[test]
    fn reopen_recovers_real_attachments() {
        let db = TestDb::new("attachrecover");
        let lease = [9u8; 16];
        let dispatcher = [5u8; 16];
        let (a, b, c);
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            a = submit(
                &mut store,
                501,
                &durable("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
                0,
            );
            b = submit(
                &mut store,
                501,
                &durable("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
                0,
            );
            c = submit(
                &mut store,
                501,
                &ram("cccccccccccccccccccccccccccccccc", 1),
                0,
            );
            for (seq, want) in [(a, 1), (b, 2), (c, 3)] {
                match store.prepare_dispatch(seq, lease, dispatcher).unwrap() {
                    PrepareOutcome::Prepared(att) => {
                        assert_eq!(att.dispatch_seq, want)
                    }
                    other => panic!("expected prepared, got {other:?}"),
                }
            }
            // Claim a toward the writer: its SUBMIT may have left.
            assert_eq!(
                store.update_operation(a, &mut |o| {
                    if let Some(d) = o.dispatch.as_mut() {
                        d.submitted = true;
                    }
                    true
                }),
                Ok(true)
            );
        }
        {
            let mut store = db.open();
            // Claimed → INDETERMINATE (resolved by QUERY, never re-run);
            // unclaimed → still DISPATCH_PREPARED, re-drivable.
            assert_eq!(
                store.get_by_seq(a).unwrap().unwrap().dispatch_state,
                DispatchState::Indeterminate
            );
            let rec_b = store.get_by_seq(b).unwrap().unwrap();
            assert_eq!(rec_b.dispatch_state, DispatchState::DispatchPrepared);
            assert!(!rec_b.dispatch.as_ref().unwrap().submitted);
            // The RAM record is gone but its consumed position is no hole:
            // a tombstone stands in for it until QUERY or SKIP settles it.
            assert!(store.get_by_seq(c).unwrap().is_none());
            let view = store.dispatch_view().unwrap();
            let tomb = view
                .iter()
                .find(|o| o.dispatch.as_ref().is_some_and(|d| d.dispatch_seq == 3))
                .expect("lane tombstone for the consumed RAM position");
            assert_eq!(tomb.dispatch_state, DispatchState::Indeterminate);
            assert!(tomb.concluded());
            assert!(tomb.canonical.is_empty(), "tombstone holds no payload");
            assert!(tomb.payload.is_empty());
            assert!(tomb.dispatch.as_ref().unwrap().submitted);
            // The allocator resumes: the next binding is seq 4, never a
            // re-issue of a seq the device may still hold. The restart
            // sealed epoch 1, so the new send mints a fresh epoch first.
            assert_eq!(store.open_epoch((501, 1), 0), Ok((2, true)));
            let d = submit(
                &mut store,
                501,
                &durable("dddddddddddddddddddddddddddddddd", 2),
                0,
            );
            match store.prepare_dispatch(d, lease, dispatcher).unwrap() {
                PrepareOutcome::Prepared(att) => assert_eq!(att.dispatch_seq, 4),
                other => panic!("expected prepared, got {other:?}"),
            }
        }
    }

    /// A vetoed mutation must leave the record untouched on every
    /// non-durable path too — same rule as the durable rollback.
    #[test]
    fn update_veto_leaves_record_untouched() {
        let db = TestDb::new("veto");
        let mut store = db.open();
        store.open_epoch((501, 1), 0).unwrap();
        let d = submit(
            &mut store,
            501,
            &durable("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
            0,
        );
        let r = submit(
            &mut store,
            501,
            &ram("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
            0,
        );
        for seq in [d, r] {
            assert_eq!(
                store.update_operation(seq, &mut |o| {
                    o.dispatch_state = DispatchState::Indeterminate;
                    o.terminal_ms = Some(7);
                    false
                }),
                Ok(false)
            );
            let op = store.get_by_seq(seq).unwrap().unwrap();
            assert_eq!(op.dispatch_state, DispatchState::HostQueued);
            assert_eq!(op.terminal_ms, None);
        }
    }

    /// Single-writer: a second daemon opening the same file fails fast
    /// instead of racing recovery, overlays and the rate budget.
    #[test]
    fn second_opener_is_refused() {
        let db = TestDb::new("singlewriter");
        let store = db.open();
        let err = SqliteOperationStore::open(&db.path).unwrap_err();
        assert!(err.message.contains("STORE_RECOVERY_REQUIRED"), "{err}");
        drop(store);
        // Locks release with the holder's connection.
        let _again = db.open();
    }

    /// The byte cap gates only new records: identity (Replay/Conflict)
    /// resolves first, matching the memory provider's ordering.
    #[test]
    fn byte_cap_gates_new_records_not_dedup() {
        let db = TestDb::new("byteorder");
        let mut store = db.open();
        store.open_epoch((501, 1), 0).unwrap();
        let req = durable("00112233445566778899aabbccddeeff", 1);
        assert_eq!(submit(&mut store, 501, &req, 0), 1);
        // Push the measured footprint past the cap with a stray -journal
        // sidecar: unused in WAL mode but counted like -wal/-shm.
        let mut sidecar = db.path.as_os_str().to_os_string();
        sidecar.push("-journal");
        std::fs::write(&sidecar, vec![0u8; STORE_BYTES_CAP as usize + 1]).unwrap();
        // Identity resolves before quota: the replay is still answered.
        match store.submit(501, &req, 1) {
            SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
            other => panic!("expected replay, got {}", outcome_name(&other)),
        }
        // New keys refuse under exhaustion.
        assert!(matches!(
            store.submit(501, &durable("ffffffffffffffffffffffffffffffff", 1), 1),
            SubmitOutcome::NoCapacity
        ));
        let _ = std::fs::remove_file(&sidecar);
    }

    /// Fresh stores are created owner-only — payloads live in the file.
    #[cfg(unix)]
    #[test]
    fn fresh_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let db = TestDb::new("perms");
        let _store = db.open();
        let mode = std::fs::metadata(&db.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// The reviewer's double-send repro: a RAM_ONLY op resubmitted under
    /// its still-open epoch after a restart must NOT be re-admitted with
    /// a new sequence — the dedup map is volatile, so the epoch itself is
    /// sealed and old keys fail closed. Durable keys still replay.
    #[test]
    fn restart_seals_open_epoch_against_ram_replays() {
        let db = TestDb::new("epochseal");
        let ram_req = ram("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
        let durable_req = durable("00112233445566778899aabbccddeeff", 1);
        {
            let mut store = db.open();
            assert_eq!(store.open_epoch((501, 1), 0), Ok((1, true)));
            assert_eq!(submit(&mut store, 501, &durable_req, 0), 1);
            assert_eq!(submit(&mut store, 501, &ram_req, 0), 2);
        }
        {
            let mut store = db.open();
            // Same request, same lineage, same epoch: refused as
            // EPOCH_CLOSED, never re-issued as a new operation.
            assert!(matches!(
                store.submit(501, &ram_req, 100),
                SubmitOutcome::EpochClosed
            ));
            let identity = OpIdentity {
                principal: Principal::UnixUid(501),
                network: 1,
                epoch: 1,
                key: ram_req.key,
            };
            assert!(store.get_by_key(&identity).unwrap().is_none());
            // A durable key under the sealed epoch still replays —
            // identity resolves before the epoch check.
            match store.submit(501, &durable_req, 100) {
                SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
                other => panic!("expected replay, got {}", outcome_name(&other)),
            }
            // A key never issued under the sealed epoch fails closed too.
            assert!(matches!(
                store.submit(501, &ram("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1), 100),
                SubmitOutcome::EpochClosed
            ));
            // New sends mint a fresh epoch and never reuse a sequence.
            assert_eq!(store.open_epoch((501, 1), 100), Ok((2, true)));
            assert_eq!(
                submit(
                    &mut store,
                    501,
                    &ram("cccccccccccccccccccccccccccccccc", 2),
                    100
                ),
                3
            );
        }
    }

    /// The DB and every sidecar (-wal/-shm) stay owner-only on a
    /// world-searchable directory — the protection comes from the file
    /// modes, not from a private parent — and reopening a store whose
    /// files were loosened to 0644 tightens them again instead of
    /// serving a WAL a different UID could read around the API ACL.
    #[cfg(unix)]
    #[test]
    fn store_files_stay_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "routeloom-cap1-perms-{}-{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let db = TestDb {
            path: dir.join("store.db"),
        };
        let assert_all_owner_only = |dir: &Path| {
            let entries: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            // EXCLUSIVE locking keeps the wal-index in heap memory, so
            // -shm may legitimately never exist — whatever SQLite did
            // create must be owner-only.
            assert!(
                entries.len() >= 2,
                "expected db plus WAL sidecar, got {entries:?}"
            );
            for file in entries {
                let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} is {mode:o}", file.display());
            }
        };
        {
            let mut store = db.open();
            store.open_epoch((501, 1), 0).unwrap();
            submit(
                &mut store,
                501,
                &durable("00112233445566778899aabbccddeeff", 1),
                0,
            );
            assert_all_owner_only(&dir);
        }
        // Loosen everything to what a permissive umask once produced —
        // reopen must repair it, not warn-and-continue.
        for entry in std::fs::read_dir(&dir).unwrap() {
            let file = entry.unwrap().path();
            if file.is_file() {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        {
            let mut store = db.open();
            // The restart sealed epoch 1 — admit under a fresh epoch.
            assert_eq!(store.open_epoch((501, 1), 1), Ok((2, true)));
            submit(
                &mut store,
                501,
                &durable("11111111111111111111111111111111", 2),
                1,
            );
            assert_all_owner_only(&dir);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn issue(op: u8, kind: u8) -> IssueIdentity {
        IssueIdentity {
            kind,
            op_id: [op; 16],
            target: 0x99,
            namespace: 1,
            profile: crate::send_store::ISSUE_PROFILE_DEV,
            authority: 0x42,
            generation: 1,
            network: 0xAAAA,
        }
    }

    #[test]
    fn issue_outbox_survives_reopen_without_reuse() {
        // T09 durable leg: the reserve → bind → sign halves persist,
        // a reopen resumes numbering (never reuses), the identity stays
        // pinned, and a pre-outbox sequence cursor migrates forward.
        let db = TestDb::new("issue-outbox");
        let mut store = db.open();
        assert_eq!(
            store.issue_reserve_tx(&issue(1, crate::send_store::ISSUE_KIND_PERMIT)),
            Ok(1)
        );
        store.issue_bind_tx(&[1; 16], b"canon-1").unwrap();
        store.issue_signed_tx(&[1; 16], b"signed-1").unwrap();
        assert_eq!(
            store.issue_reserve_tx(&issue(2, crate::send_store::ISSUE_KIND_RECOVERY)),
            Ok(2)
        );
        drop(store);
        let mut reopened = db.open();
        // Both halves survived the reopen; the unsigned recovery leg
        // reports None until it is bound and signed.
        assert_eq!(
            reopened.issue_original_row(&[1; 16]),
            Some((b"canon-1".to_vec(), b"signed-1".to_vec()))
        );
        assert_eq!(reopened.issue_original_row(&[2; 16]), None);
        // Numbering resumes at 3 — the consumed 1..=2 never repeat —
        // and the pinned identity still refuses a rotated generation.
        assert_eq!(
            reopened.issue_reserve_tx(&issue(3, crate::send_store::ISSUE_KIND_PERMIT)),
            Ok(3)
        );
        let mut rotated = issue(4, crate::send_store::ISSUE_KIND_PERMIT);
        rotated.generation = 2;
        assert_eq!(
            reopened.issue_reserve_tx(&rotated),
            Err(IssueRefusal::IdentityChanged)
        );
        // A same-opid, same-kind re-reserve after the crash replays the
        // bound sequence instead of consuming a new one.
        assert_eq!(
            reopened.issue_reserve_tx(&issue(2, crate::send_store::ISSUE_KIND_RECOVERY)),
            Ok(2)
        );
    }

    #[test]
    fn issue_outbox_migrates_v2_and_preserves_unresolved_rows() {
        let db = TestDb::new("issue-v2-outbox");
        let store = db.open();
        store.conn.execute("DROP TABLE config_outbox", []).unwrap();
        let v2_outbox = CONFIG_OUTBOX_SQL.replace(", terminal INTEGER NOT NULL DEFAULT 0", "");
        store.conn.execute_batch(&v2_outbox).unwrap();
        let first = issue(1, crate::send_store::ISSUE_KIND_PERMIT);
        store
            .conn
            .execute(
                "INSERT INTO config_outbox(opid, kind, target, ns, profile, authority, \
                 generation, network, sequence, canonical, signed) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    first.op_id.to_vec(),
                    first.kind,
                    u64_blob(first.target),
                    first.namespace,
                    first.profile,
                    u64_blob(first.authority),
                    first.generation,
                    u64_blob(first.network),
                    u64_blob(1),
                    b"canon-1",
                    b"signed-1",
                ],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE meta SET value=?1 WHERE key='schema_version'",
                params![2u32.to_be_bytes().to_vec()],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO meta(key, value) VALUES('config_auth_seq', ?1)",
                params![u64_blob(2)],
            )
            .unwrap();
        drop(store);
        let mut migrated = db.open();
        assert_eq!(migrated.issue_reserve_tx(&first), Ok(1));
        assert_eq!(
            migrated.issue_original_row(&[1; 16]),
            Some((b"canon-1".to_vec(), b"signed-1".to_vec()))
        );
        for op in 2..=crate::send_store::ISSUE_OUTBOX_CAP as u8 {
            migrated
                .issue_reserve_tx(&issue(op, crate::send_store::ISSUE_KIND_PERMIT))
                .unwrap();
        }
        assert_eq!(
            migrated.issue_reserve_tx(&issue(200, crate::send_store::ISSUE_KIND_PERMIT)),
            Err(IssueRefusal::Capacity)
        );
        assert_eq!(
            migrated.issue_original_row(&[1; 16]),
            Some((b"canon-1".to_vec(), b"signed-1".to_vec()))
        );
        migrated.issue_complete_tx(&[1; 16]).unwrap();
        assert_eq!(
            migrated.issue_reserve_tx(&issue(200, crate::send_store::ISSUE_KIND_PERMIT)),
            Ok(crate::send_store::ISSUE_OUTBOX_CAP as u64 + 1)
        );
        assert_eq!(migrated.issue_original_row(&[1; 16]), None);
    }

    #[test]
    fn issue_outbox_migrates_a_legacy_sequence_cursor() {
        // A database that only ever ran the pre-outbox allocator keeps
        // its cursor: the next reservation continues numbering and pins
        // the issuing identity.
        let db = TestDb::new("issue-migrate");
        let store = db.open();
        store
            .conn
            .execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('config_auth_seq', ?1)",
                params![u64_blob(41)],
            )
            .unwrap();
        drop(store);
        let mut migrated = db.open();
        assert_eq!(
            migrated.issue_reserve_tx(&issue(1, crate::send_store::ISSUE_KIND_PERMIT)),
            Ok(41)
        );
        assert_eq!(
            migrated.issue_reserve_tx(&issue(2, crate::send_store::ISSUE_KIND_PERMIT)),
            Ok(42)
        );
        let mut rotated = issue(3, crate::send_store::ISSUE_KIND_PERMIT);
        rotated.authority = 0x777;
        assert_eq!(
            migrated.issue_reserve_tx(&rotated),
            Err(IssueRefusal::IdentityChanged)
        );
    }
}
