//! Site Authority persistence (docs/design/sdk-v1/07 §3).
//!
//! The authority keeps its whole model in RAM (it is small and bounded:
//! members ≤ [`super::DEVICE_CAP`], discovered ≤ 1024, join requests ≤ 256)
//! and writes every change through one atomic [`Batch`]. A batch is the
//! unit of the 07 §3 crash rule: the ledger entry, the device row, the
//! issued MemberCert (or RRS1) and the counters commit together or not at
//! all, and nothing that depends on them (message_4, an API `committed`
//! answer, an event) happens before `commit` returned Ok.
//!
//! SQLite layout (`site.db`, created 0600, exclusive lock, FULL sync):
//!
//! | table | key | content |
//! |---|---|---|
//! | `meta` | name | schema version, site binding, policy, counters (rs_epoch, next serial, revision, ledger head), GK high-water / activation / last rotation |
//! | `devices` | node | kid, DevCert, state member/removed, generation, role, MemberCert + serial, confirm state, DAMS, timestamps, removal |
//! | `ledger` | seq | approve/revoke entries in a SHA-256 hash chain |
//! | `rrs` | rs_epoch | every issued RRS1 object |
//! | `group_keys` | gk_epoch | GK bytes + state (active + staged at most) |
//! | `gk_rotation` | (single row) | the live rotation, if any (G-SEC P5 §6.1) |
//! | `gk_targets` | (rotation, node) | one row per member of the live rotation |
//! | `docs` | (kind, key) | bookkeeping JSON: discovered devices, join requests, decisions, operations |
//!
//! Schema 2 adds the rotation tables and the GK `meta` keys; a version-1
//! database migrates inside one transaction at open (refusing corrupt key
//! tables outright), unknown versions refuse to start.
//!
//! Secrets at rest: DAMS and GK sit in the database file, protected by its
//! 0600 mode only — the 07 §3 "host-key sealing" is not implemented (no TPM
//! seam yet). The SAK is not here: it stays in its own 0600 key file behind
//! the `RootSigner` seam.

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

use super::group_keys::{
    validate_group_keys, RotationCause, RotationPhase, RotationRow, TargetRow, TargetState,
    META_HIGH_WATER,
};

pub const SCHEMA_VERSION: u32 = 2;
/// The pre-P5 layout (no rotation tables, no GK meta): migrated at open.
const SCHEMA_VERSION_1: u32 = 1;

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self(format!("site store: {error}"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DocKind {
    Discovered,
    JoinRequest,
    Decision,
    Operation,
}

impl DocKind {
    fn name(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::JoinRequest => "join_request",
            Self::Decision => "decision",
            Self::Operation => "operation",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "discovered" => Self::Discovered,
            "join_request" => Self::JoinRequest,
            "decision" => Self::Decision,
            "operation" => Self::Operation,
            _ => return None,
        })
    }
}

/// One member / removed device (the `devices` table).
#[derive(Clone, Default, Eq, PartialEq)]
pub struct DeviceRow {
    pub node: u64,
    pub kid: [u8; 32],
    pub dev_cert: Vec<u8>,
    pub model: u16,
    pub hw_rev: u8,
    pub cert_serial: u32,
    /// true = member, false = removed.
    pub member: bool,
    pub generation: u32,
    pub role: u8,
    pub member_cert: Vec<u8>,
    pub member_cert_serial: u32,
    /// false = allowed_unconfirmed, true = active (JoinConfirm seen).
    pub confirmed: bool,
    /// Latest DAMS (EDHOC Exporter 32771), zero before the first delivery.
    pub dams: [u8; 32],
    pub approved_ms: u64,
    pub delivered_ms: Option<u64>,
    pub confirmed_ms: Option<u64>,
    pub last_seen_ms: Option<u64>,
    pub removed_ms: Option<u64>,
    pub removal_reason: u8,
}

impl std::fmt::Debug for DeviceRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRow")
            .field("node", &self.node)
            .field("member", &self.member)
            .field("generation", &self.generation)
            .field("role", &self.role)
            .field("confirmed", &self.confirmed)
            .field("dams", &"<redacted>")
            .finish()
    }
}

impl Drop for DeviceRow {
    fn drop(&mut self) {
        self.dams.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerRow {
    pub seq: u64,
    /// "approve", "revoke", "reissue" or "cutover".
    pub kind: String,
    pub node: u64,
    pub kid: [u8; 32],
    pub generation: u32,
    /// SHA-256 of the MemberCert (approve/reissue), of the RRS1 object
    /// (revoke) or of the CutoverCommit object (cutover).
    pub digest: [u8; 32],
    pub ms: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Eq, PartialEq)]
pub struct GroupKeyRow {
    pub epoch: u32,
    pub key: [u8; 32],
    /// "active" or "staged".
    pub state: String,
    pub created_ms: u64,
}

impl std::fmt::Debug for GroupKeyRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupKeyRow")
            .field("epoch", &self.epoch)
            .field("key", &"<redacted>")
            .field("state", &self.state)
            .field("created_ms", &self.created_ms)
            .finish()
    }
}

impl Drop for GroupKeyRow {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// What a batch does to the single `gk_rotation` row.
#[derive(Default)]
pub enum RotationWrite {
    #[default]
    Keep,
    /// Replaces the row (supersede) or creates it (new staging).
    Upsert(RotationRow),
    /// Deletes the row (convergence; targets go with `gk_targets_clear`).
    Delete,
}

/// One atomic write.
#[derive(Default)]
pub struct Batch {
    pub meta: Vec<(&'static str, Vec<u8>)>,
    pub devices: Vec<DeviceRow>,
    pub ledger: Vec<LedgerRow>,
    pub rrs: Vec<(u32, Vec<u8>)>,
    pub group_keys: Vec<GroupKeyRow>,
    /// Delete group keys with an epoch below this.
    pub group_keys_below: Option<u32>,
    /// Delete exactly these group-key epochs (superseded staged keys).
    pub group_keys_delete: Vec<u32>,
    pub gk_rotation: RotationWrite,
    /// Deletes every `gk_targets` row (only one rotation lives at a time).
    pub gk_targets_clear: bool,
    pub gk_targets: Vec<TargetRow>,
    /// `(kind, key, Some(json))` upserts, `None` deletes.
    pub docs: Vec<(DocKind, String, Option<String>)>,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.meta.is_empty()
            && self.devices.is_empty()
            && self.ledger.is_empty()
            && self.rrs.is_empty()
            && self.group_keys.is_empty()
            && self.group_keys_below.is_none()
            && self.group_keys_delete.is_empty()
            && matches!(self.gk_rotation, RotationWrite::Keep)
            && !self.gk_targets_clear
            && self.gk_targets.is_empty()
            && self.docs.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub meta: BTreeMap<String, Vec<u8>>,
    pub devices: Vec<DeviceRow>,
    pub ledger: Vec<LedgerRow>,
    pub rrs: Vec<(u32, Vec<u8>)>,
    pub group_keys: Vec<GroupKeyRow>,
    pub gk_rotation: Option<RotationRow>,
    pub gk_targets: Vec<TargetRow>,
    pub docs: BTreeMap<(DocKind, String), String>,
}

impl Snapshot {
    fn apply(&mut self, batch: &Batch) {
        for (name, value) in &batch.meta {
            self.meta.insert((*name).to_string(), value.clone());
        }
        for row in &batch.devices {
            self.devices.retain(|d| d.node != row.node);
            self.devices.push(row.clone());
        }
        self.ledger.extend(batch.ledger.iter().cloned());
        for (epoch, object) in &batch.rrs {
            self.rrs.retain(|(e, _)| e != epoch);
            self.rrs.push((*epoch, object.clone()));
        }
        for row in &batch.group_keys {
            self.group_keys.retain(|g| g.epoch != row.epoch);
            self.group_keys.push(row.clone());
        }
        if let Some(below) = batch.group_keys_below {
            self.group_keys.retain(|g| g.epoch >= below);
        }
        for epoch in &batch.group_keys_delete {
            self.group_keys.retain(|g| &g.epoch != epoch);
        }
        match &batch.gk_rotation {
            RotationWrite::Keep => {}
            RotationWrite::Upsert(row) => self.gk_rotation = Some(row.clone()),
            RotationWrite::Delete => self.gk_rotation = None,
        }
        if batch.gk_targets_clear {
            self.gk_targets.clear();
        }
        for row in &batch.gk_targets {
            self.gk_targets
                .retain(|t| (t.rotation, t.node) != (row.rotation, row.node));
            self.gk_targets.push(row.clone());
        }
        for (kind, key, body) in &batch.docs {
            match body {
                Some(json) => {
                    self.docs.insert((*kind, key.clone()), json.clone());
                }
                None => {
                    self.docs.remove(&(*kind, key.clone()));
                }
            }
        }
    }
}

pub trait SiteStore: Send {
    fn load(&mut self) -> Result<Snapshot, StoreError>;
    fn commit(&mut self, batch: &Batch) -> Result<(), StoreError>;
    /// True when a commit survives a host restart.
    fn durable(&self) -> bool;
    /// Ledger rows for one node, by seq (the old-kid recovery lookup,
    /// 04 §5.4). The default scans the snapshot; SQLite answers by
    /// index, without loading the whole history into RAM.
    fn ledger_for(&mut self, node: u64) -> Result<Vec<LedgerRow>, StoreError> {
        Ok(self
            .load()?
            .ledger
            .into_iter()
            .filter(|row| row.node == node)
            .collect())
    }
    /// Existence check for the v1 NodeId reuse rule. Stores may answer it
    /// without materializing the node's full, unbounded ledger history.
    fn has_revocation(&mut self, node: u64) -> Result<bool, StoreError> {
        Ok(self
            .ledger_for(node)?
            .iter()
            .any(|row| row.kind == "revoke"))
    }
}

/// RAM store for tests; `fail_next` injects a commit failure (the
/// ledger-failure path of 02 §8: AuthorityBusy, never success).
#[derive(Default)]
pub struct MemoryStore {
    snapshot: Snapshot,
    pub fail_next: usize,
}

impl SiteStore for MemoryStore {
    fn load(&mut self) -> Result<Snapshot, StoreError> {
        Ok(self.snapshot.clone())
    }
    fn commit(&mut self, batch: &Batch) -> Result<(), StoreError> {
        if self.fail_next > 0 {
            self.fail_next -= 1;
            return Err(StoreError("injected commit failure".into()));
        }
        self.snapshot.apply(batch);
        Ok(())
    }
    fn durable(&self) -> bool {
        false
    }
}

pub struct SqliteSiteStore {
    conn: Connection,
}

fn i(value: u64) -> i64 {
    value as i64
}

fn u(value: i64) -> u64 {
    value as u64
}

fn checked_u32(value: i64, field: &str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| StoreError(format!("site store: {field} is out of range")))
}

fn arr32(mut bytes: Vec<u8>, what: &str) -> Result<[u8; 32], StoreError> {
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(StoreError(format!("site store: {what} is not 32 bytes")));
    }
    let mut out = [0; 32];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

impl SqliteSiteStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let fresh = !path.exists();
        if fresh {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| {
                        StoreError(format!("cannot create site store {}: {e}", path.display()))
                    })?;
            }
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)
                    .map_err(|e| StoreError(format!("site store {}: {e}", path.display())))?
                    .permissions()
                    .mode();
                if mode & 0o077 != 0 {
                    return Err(StoreError(format!(
                        "site store {} is group/other accessible (mode {:o}); it holds DAMS and GK — chmod 600",
                        path.display(),
                        mode & 0o777
                    )));
                }
            }
        }
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "busy_timeout", 100)?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        if fresh {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS devices (
                node INTEGER PRIMARY KEY, kid BLOB NOT NULL, dev_cert BLOB NOT NULL,
                model INTEGER NOT NULL, hw_rev INTEGER NOT NULL, cert_serial INTEGER NOT NULL,
                member INTEGER NOT NULL, generation INTEGER NOT NULL, role INTEGER NOT NULL,
                member_cert BLOB NOT NULL, member_cert_serial INTEGER NOT NULL,
                confirmed INTEGER NOT NULL, dams BLOB NOT NULL, approved_ms INTEGER NOT NULL,
                delivered_ms INTEGER, confirmed_ms INTEGER, last_seen_ms INTEGER,
                removed_ms INTEGER, removal_reason INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS ledger (
                seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, node INTEGER NOT NULL,
                kid BLOB NOT NULL, generation INTEGER NOT NULL, digest BLOB NOT NULL,
                ms INTEGER NOT NULL, hash BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS rrs (rs_epoch INTEGER PRIMARY KEY, object BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS group_keys (
                gk_epoch INTEGER PRIMARY KEY, gk BLOB NOT NULL, state TEXT NOT NULL,
                created_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS gk_rotation (
                operation_id INTEGER PRIMARY KEY, from_epoch INTEGER NOT NULL,
                to_epoch INTEGER NOT NULL, cause INTEGER NOT NULL, phase TEXT NOT NULL,
                members_revision INTEGER NOT NULL, created_ms INTEGER NOT NULL,
                activated_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS gk_targets (
                rotation INTEGER NOT NULL, node INTEGER NOT NULL, kid BLOB NOT NULL,
                generation INTEGER NOT NULL, state TEXT NOT NULL,
                confirmed_epoch INTEGER NOT NULL, confirmed_gkid BLOB,
                last_contact_ms INTEGER, PRIMARY KEY (rotation, node));
             CREATE TABLE IF NOT EXISTS docs (
                kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (kind, key));
             CREATE INDEX IF NOT EXISTS ledger_node_idx ON ledger (node);",
            )?;
            conn.execute(
                "INSERT INTO meta (name, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION.to_be_bytes().to_vec()],
            )?;
            return Ok(Self { conn });
        }
        let version: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM meta WHERE name='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match version {
            None => {
                return Err(StoreError(format!(
                    "site store {} has no schema version",
                    path.display()
                )))
            }
            Some(v) if v == SCHEMA_VERSION.to_be_bytes() => {}
            Some(v) if v == SCHEMA_VERSION_1.to_be_bytes() => {
                Self::migrate_1_to_2(&mut conn, path)?;
            }
            Some(_) => {
                return Err(StoreError(format!(
                    "site store {} has an unknown schema version",
                    path.display()
                )))
            }
        }
        // Additive, versionless: old databases gain the recovery index
        // on open (no data moves, no version bump).
        conn.execute_batch("CREATE INDEX IF NOT EXISTS ledger_node_idx ON ledger (node);")?;
        Ok(Self { conn })
    }

    /// Version 1 → 2 inside one transaction: empty tables gain nothing but
    /// the version bump (a fresh database still mints epoch 1 through the
    /// authority); a used database validates its key table and records the
    /// high-water mark. A corrupt key table refuses to migrate, and the
    /// version bump never lands without the validation.
    fn migrate_1_to_2(conn: &mut Connection, path: &Path) -> Result<(), StoreError> {
        let tx = conn.transaction()?;
        tx.execute_batch(
            "CREATE TABLE gk_rotation (
                operation_id INTEGER PRIMARY KEY, from_epoch INTEGER NOT NULL,
                to_epoch INTEGER NOT NULL, cause INTEGER NOT NULL, phase TEXT NOT NULL,
                members_revision INTEGER NOT NULL, created_ms INTEGER NOT NULL,
                activated_ms INTEGER NOT NULL);
             CREATE TABLE gk_targets (
                rotation INTEGER NOT NULL, node INTEGER NOT NULL, kid BLOB NOT NULL,
                generation INTEGER NOT NULL, state TEXT NOT NULL,
                confirmed_epoch INTEGER NOT NULL, confirmed_gkid BLOB,
                last_contact_ms INTEGER, PRIMARY KEY (rotation, node));",
        )?;
        let used: i64 = tx.query_row(
            "SELECT (SELECT COUNT(*) FROM devices) + (SELECT COUNT(*) FROM ledger)
                    + (SELECT COUNT(*) FROM group_keys)
                    + (SELECT COUNT(*) FROM rrs) + (SELECT COUNT(*) FROM docs)
                    + (SELECT COUNT(*) FROM meta WHERE name <> 'schema_version')",
            [],
            |row| row.get(0),
        )?;
        if used > 0 {
            let mut stmt = tx.prepare("SELECT gk_epoch, gk, state, created_ms FROM group_keys")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?;
            let mut keys = Vec::new();
            for row in rows {
                let (epoch, key, state, created) = row?;
                keys.push(GroupKeyRow {
                    epoch: checked_u32(epoch, "gk_epoch")?,
                    key: arr32(key, "gk").map_err(|e| {
                        StoreError(format!("cannot migrate {}: {e}", path.display()))
                    })?,
                    state,
                    created_ms: u(created),
                });
            }
            let valid = validate_group_keys(&keys, false)
                .map_err(|e| StoreError(format!("cannot migrate {}: {e}", path.display())))?;
            tx.execute(
                "INSERT INTO meta (name, value) VALUES (?1, ?2)",
                params![META_HIGH_WATER, valid.high_water.to_be_bytes().to_vec()],
            )?;
        }
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE name = 'schema_version'",
            params![SCHEMA_VERSION.to_be_bytes().to_vec()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

impl SiteStore for SqliteSiteStore {
    fn load(&mut self) -> Result<Snapshot, StoreError> {
        let mut snapshot = Snapshot::default();
        let mut stmt = self.conn.prepare("SELECT name, value FROM meta")?;
        for row in stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })? {
            let (name, value) = row?;
            snapshot.meta.insert(name, value);
        }
        let mut stmt = self.conn.prepare(
            "SELECT node, kid, dev_cert, model, hw_rev, cert_serial, member, generation, role,
                    member_cert, member_cert_serial, confirmed, dams, approved_ms, delivered_ms,
                    confirmed_ms, last_seen_ms, removed_ms, removal_reason FROM devices",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                (
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                ),
                (
                    r.get::<_, bool>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                ),
                (
                    r.get::<_, Vec<u8>>(9)?,
                    r.get::<_, i64>(10)?,
                    r.get::<_, bool>(11)?,
                ),
                r.get::<_, Vec<u8>>(12)?,
                (
                    r.get::<_, i64>(13)?,
                    r.get::<_, Option<i64>>(14)?,
                    r.get::<_, Option<i64>>(15)?,
                    r.get::<_, Option<i64>>(16)?,
                    r.get::<_, Option<i64>>(17)?,
                ),
                r.get::<_, i64>(18)?,
            ))
        })?;
        for row in rows {
            let (
                node,
                kid,
                dev_cert,
                (model, hw_rev, serial),
                (member, generation, role),
                (mc, mcs, confirmed),
                dams,
                times,
                reason,
            ) = row?;
            snapshot.devices.push(DeviceRow {
                node: u(node),
                kid: arr32(kid, "kid")?,
                dev_cert,
                model: model as u16,
                hw_rev: hw_rev as u8,
                cert_serial: serial as u32,
                member,
                generation: generation as u32,
                role: role as u8,
                member_cert: mc,
                member_cert_serial: mcs as u32,
                confirmed,
                dams: arr32(dams, "dams")?,
                approved_ms: u(times.0),
                delivered_ms: times.1.map(u),
                confirmed_ms: times.2.map(u),
                last_seen_ms: times.3.map(u),
                removed_ms: times.4.map(u),
                removal_reason: reason as u8,
            });
        }
        let mut stmt = self.conn.prepare(
            "SELECT seq, kind, node, kid, generation, digest, ms, hash FROM ledger ORDER BY seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?;
        for row in rows {
            let (seq, kind, node, kid, generation, digest, ms, hash) = row?;
            snapshot.ledger.push(LedgerRow {
                seq: u(seq),
                kind,
                node: u(node),
                kid: arr32(kid, "ledger kid")?,
                generation: generation as u32,
                digest: arr32(digest, "ledger digest")?,
                ms: u(ms),
                hash: arr32(hash, "ledger hash")?,
            });
        }
        let mut stmt = self
            .conn
            .prepare("SELECT rs_epoch, object FROM rrs ORDER BY rs_epoch")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))? {
            let (epoch, object) = row?;
            snapshot.rrs.push((epoch as u32, object));
        }
        let mut stmt = self
            .conn
            .prepare("SELECT gk_epoch, gk, state, created_ms FROM group_keys ORDER BY gk_epoch")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (epoch, key, state, created) = row?;
            snapshot.group_keys.push(GroupKeyRow {
                epoch: checked_u32(epoch, "gk_epoch")?,
                key: arr32(key, "gk")?,
                state,
                created_ms: u(created),
            });
        }
        let mut stmt = self.conn.prepare(
            "SELECT operation_id, from_epoch, to_epoch, cause, phase,
                    members_revision, created_ms, activated_ms FROM gk_rotation",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })?;
        for row in rows {
            if snapshot.gk_rotation.is_some() {
                return Err(StoreError("site store: two gk_rotation rows".into()));
            }
            let (op, from, to, cause, phase, revision, created, activated) = row?;
            let cause = u8::try_from(cause)
                .ok()
                .and_then(RotationCause::parse)
                .ok_or_else(|| StoreError("site store: gk_rotation cause corrupt".into()))?;
            let phase = RotationPhase::parse(&phase)
                .ok_or_else(|| StoreError("site store: gk_rotation phase corrupt".into()))?;
            snapshot.gk_rotation = Some(RotationRow {
                operation_id: u(op),
                from_epoch: checked_u32(from, "gk_rotation from_epoch")?,
                to_epoch: checked_u32(to, "gk_rotation to_epoch")?,
                cause,
                phase,
                members_revision: checked_u32(revision, "gk_rotation members_revision")?,
                created_ms: u(created),
                activated_ms: u(activated),
            });
        }
        let mut stmt = self.conn.prepare(
            "SELECT rotation, node, kid, generation, state, confirmed_epoch,
                    confirmed_gkid, last_contact_ms FROM gk_targets ORDER BY node",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<Vec<u8>>>(6)?,
                r.get::<_, Option<i64>>(7)?,
            ))
        })?;
        for row in rows {
            let (rotation, node, kid, generation, state, confirmed, gkid, contact) = row?;
            let state = TargetState::parse(&state)
                .ok_or_else(|| StoreError("site store: gk_targets state corrupt".into()))?;
            let confirmed_gkid = gkid
                .map(|bytes| arr32(bytes, "gk target gkid"))
                .transpose()?;
            snapshot.gk_targets.push(TargetRow {
                rotation: u(rotation),
                node: u(node),
                kid: arr32(kid, "gk target kid")?,
                generation: checked_u32(generation, "gk target generation")?,
                state,
                confirmed_epoch: checked_u32(confirmed, "gk target confirmed_epoch")?,
                confirmed_gkid,
                last_contact_ms: contact.map(u),
            });
        }
        let mut stmt = self.conn.prepare("SELECT kind, key, body FROM docs")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (kind, key, body) = row?;
            let kind = DocKind::parse(&kind)
                .ok_or_else(|| StoreError(format!("site store: unknown doc kind {kind}")))?;
            snapshot.docs.insert((kind, key), body);
        }
        Ok(snapshot)
    }

    fn ledger_for(&mut self, node: u64) -> Result<Vec<LedgerRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, kind, node, kid, generation, digest, ms, hash FROM ledger WHERE node = ?1 ORDER BY seq",
        )?;
        let rows = stmt.query_map(params![i(node)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, kind, node, kid, generation, digest, ms, hash) = row?;
            out.push(LedgerRow {
                seq: u(seq),
                kind,
                node: u(node),
                kid: arr32(kid, "ledger kid")?,
                generation: generation as u32,
                digest: arr32(digest, "ledger digest")?,
                ms: u(ms),
                hash: arr32(hash, "ledger hash")?,
            });
        }
        Ok(out)
    }

    fn has_revocation(&mut self, node: u64) -> Result<bool, StoreError> {
        let found: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ledger WHERE node = ?1 AND kind = 'revoke')",
            params![i(node)],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }

    fn commit(&mut self, batch: &Batch) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        for (name, value) in &batch.meta {
            tx.execute(
                "INSERT INTO meta (name, value) VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                params![name, value],
            )?;
        }
        for d in &batch.devices {
            let dams = Zeroizing::new(d.dams.to_vec());
            tx.execute(
                "INSERT OR REPLACE INTO devices (node, kid, dev_cert, model, hw_rev, cert_serial,
                    member, generation, role, member_cert, member_cert_serial, confirmed, dams,
                    approved_ms, delivered_ms, confirmed_ms, last_seen_ms, removed_ms, removal_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                params![
                    i(d.node),
                    d.kid.to_vec(),
                    d.dev_cert,
                    i64::from(d.model),
                    i64::from(d.hw_rev),
                    i64::from(d.cert_serial),
                    d.member,
                    i64::from(d.generation),
                    i64::from(d.role),
                    d.member_cert,
                    i64::from(d.member_cert_serial),
                    d.confirmed,
                    dams.as_slice(),
                    i(d.approved_ms),
                    d.delivered_ms.map(i),
                    d.confirmed_ms.map(i),
                    d.last_seen_ms.map(i),
                    d.removed_ms.map(i),
                    i64::from(d.removal_reason),
                ],
            )?;
        }
        for l in &batch.ledger {
            tx.execute(
                "INSERT INTO ledger (seq, kind, node, kid, generation, digest, ms, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    i(l.seq),
                    l.kind,
                    i(l.node),
                    l.kid.to_vec(),
                    i64::from(l.generation),
                    l.digest.to_vec(),
                    i(l.ms),
                    l.hash.to_vec()
                ],
            )?;
        }
        for (epoch, object) in &batch.rrs {
            tx.execute(
                "INSERT INTO rrs (rs_epoch, object) VALUES (?1, ?2)",
                params![i64::from(*epoch), object],
            )?;
        }
        for g in &batch.group_keys {
            let key = Zeroizing::new(g.key.to_vec());
            tx.execute(
                "INSERT OR REPLACE INTO group_keys (gk_epoch, gk, state, created_ms) VALUES (?1, ?2, ?3, ?4)",
                params![i64::from(g.epoch), key.as_slice(), g.state, i(g.created_ms)],
            )?;
        }
        if let Some(below) = batch.group_keys_below {
            tx.execute(
                "DELETE FROM group_keys WHERE gk_epoch < ?1",
                params![i64::from(below)],
            )?;
        }
        for epoch in &batch.group_keys_delete {
            tx.execute(
                "DELETE FROM group_keys WHERE gk_epoch = ?1",
                params![i64::from(*epoch)],
            )?;
        }
        match &batch.gk_rotation {
            RotationWrite::Keep => {}
            RotationWrite::Upsert(row) => {
                tx.execute("DELETE FROM gk_rotation", [])?;
                tx.execute(
                    "INSERT INTO gk_rotation (operation_id, from_epoch, to_epoch, cause, phase,
                        members_revision, created_ms, activated_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        i(row.operation_id),
                        i64::from(row.from_epoch),
                        i64::from(row.to_epoch),
                        i64::from(row.cause as u8),
                        row.phase.name(),
                        i64::from(row.members_revision),
                        i(row.created_ms),
                        i(row.activated_ms),
                    ],
                )?;
            }
            RotationWrite::Delete => {
                tx.execute("DELETE FROM gk_rotation", [])?;
            }
        }
        if batch.gk_targets_clear {
            tx.execute("DELETE FROM gk_targets", [])?;
        }
        for t in &batch.gk_targets {
            tx.execute(
                "INSERT OR REPLACE INTO gk_targets (rotation, node, kid, generation, state,
                    confirmed_epoch, confirmed_gkid, last_contact_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    i(t.rotation),
                    i(t.node),
                    t.kid.to_vec(),
                    i64::from(t.generation),
                    t.state.name(),
                    i64::from(t.confirmed_epoch),
                    t.confirmed_gkid.map(|g| g.to_vec()),
                    t.last_contact_ms.map(i),
                ],
            )?;
        }
        for (kind, key, body) in &batch.docs {
            match body {
                Some(json) => {
                    tx.execute(
                        "INSERT INTO docs (kind, key, body) VALUES (?1, ?2, ?3)
                         ON CONFLICT(kind, key) DO UPDATE SET body = excluded.body",
                        params![kind.name(), key, json],
                    )?;
                }
                None => {
                    tx.execute(
                        "DELETE FROM docs WHERE kind = ?1 AND key = ?2",
                        params![kind.name(), key],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn durable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-site-store-{tag}-{}-{}",
            std::process::id(),
            crate::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("site.db")
    }

    #[test]
    fn sqlite_round_trips_every_table_and_is_owner_only() {
        let path = temp_path("rt");
        let device = DeviceRow {
            node: 0x00A1_0000_0000_1234,
            kid: [7; 32],
            dev_cert: vec![1, 2, 3],
            model: 17,
            hw_rev: 2,
            cert_serial: 9,
            member: true,
            generation: 3,
            role: 1,
            member_cert: vec![4, 5],
            member_cert_serial: 44,
            confirmed: false,
            dams: [9; 32],
            approved_ms: 100,
            delivered_ms: Some(200),
            confirmed_ms: None,
            last_seen_ms: Some(300),
            removed_ms: None,
            removal_reason: 0,
        };
        {
            let mut store = SqliteSiteStore::open(&path).unwrap();
            let batch = Batch {
                meta: vec![("rs_epoch", 5_u32.to_be_bytes().to_vec())],
                devices: vec![device.clone()],
                ledger: vec![LedgerRow {
                    seq: 1,
                    kind: "approve".into(),
                    node: device.node,
                    kid: device.kid,
                    generation: 3,
                    digest: [1; 32],
                    ms: 100,
                    hash: [2; 32],
                }],
                rrs: vec![(5, vec![0xD2])],
                group_keys: vec![GroupKeyRow {
                    epoch: 1,
                    key: [3; 32],
                    state: "active".into(),
                    created_ms: 1,
                }],
                group_keys_below: None,
                group_keys_delete: Vec::new(),
                gk_rotation: RotationWrite::Keep,
                gk_targets_clear: false,
                gk_targets: Vec::new(),
                docs: vec![(DocKind::Discovered, "k".into(), Some("{}".into()))],
            };
            store.commit(&batch).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let mut store = SqliteSiteStore::open(&path).unwrap();
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.devices, vec![device]);
        assert_eq!(snapshot.ledger.len(), 1);
        assert_eq!(snapshot.rrs, vec![(5, vec![0xD2])]);
        assert_eq!(snapshot.group_keys.len(), 1);
        assert_eq!(snapshot.meta["rs_epoch"], 5_u32.to_be_bytes());
        assert_eq!(snapshot.docs[&(DocKind::Discovered, "k".to_string())], "{}");
        store
            .commit(&Batch {
                docs: vec![(DocKind::Discovered, "k".into(), None)],
                ..Batch::default()
            })
            .unwrap();
        assert!(store.load().unwrap().docs.is_empty());
        // A second opener is refused (exclusive lock held by `store`).
        let second = SqliteSiteStore::open(&path).and_then(|mut s| s.load());
        assert!(second.is_err());
        drop(store);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_failed_transaction_leaves_nothing_behind() {
        let path = temp_path("atomic");
        let mut store = SqliteSiteStore::open(&path).unwrap();
        // The second rrs row duplicates the first key: the whole batch fails.
        let batch = Batch {
            meta: vec![("rs_epoch", vec![1])],
            rrs: vec![(1, vec![1]), (1, vec![2])],
            ..Batch::default()
        };
        assert!(store.commit(&batch).is_err());
        let snapshot = store.load().unwrap();
        assert!(snapshot.rrs.is_empty());
        assert!(!snapshot.meta.contains_key("rs_epoch"));
        drop(store);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A hand-built version-1 database; `setup` adds rows after the schema.
    fn v1_db(tag: &str, setup: impl FnOnce(&rusqlite::Connection)) -> std::path::PathBuf {
        let db = temp_path(tag);
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (name TEXT PRIMARY KEY, value BLOB NOT NULL);
                 CREATE TABLE devices (
                    node INTEGER PRIMARY KEY, kid BLOB NOT NULL, dev_cert BLOB NOT NULL,
                    model INTEGER NOT NULL, hw_rev INTEGER NOT NULL, cert_serial INTEGER NOT NULL,
                    member INTEGER NOT NULL, generation INTEGER NOT NULL, role INTEGER NOT NULL,
                    member_cert BLOB NOT NULL, member_cert_serial INTEGER NOT NULL,
                    confirmed INTEGER NOT NULL, dams BLOB NOT NULL, approved_ms INTEGER NOT NULL,
                    delivered_ms INTEGER, confirmed_ms INTEGER, last_seen_ms INTEGER,
                    removed_ms INTEGER, removal_reason INTEGER NOT NULL);
                 CREATE TABLE ledger (
                    seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, node INTEGER NOT NULL,
                    kid BLOB NOT NULL, generation INTEGER NOT NULL, digest BLOB NOT NULL,
                    ms INTEGER NOT NULL, hash BLOB NOT NULL);
                 CREATE TABLE rrs (rs_epoch INTEGER PRIMARY KEY, object BLOB NOT NULL);
                 CREATE TABLE group_keys (
                    gk_epoch INTEGER PRIMARY KEY, gk BLOB NOT NULL, state TEXT NOT NULL,
                    created_ms INTEGER NOT NULL);
                 CREATE TABLE docs (
                    kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY (kind, key));",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO meta (name, value) VALUES ('schema_version', ?1)",
                rusqlite::params![SCHEMA_VERSION_1.to_be_bytes().to_vec()],
            )
            .unwrap();
            setup(&conn);
        }
        std::fs::set_permissions(&db, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        db
    }

    fn v1_key(conn: &rusqlite::Connection, epoch: u32, key: &[u8], state: &str) {
        conn.execute(
            "INSERT INTO group_keys (gk_epoch, gk, state, created_ms) VALUES (?1, ?2, ?3, 7)",
            rusqlite::params![i64::from(epoch), key, state],
        )
        .unwrap();
    }

    fn v1_member(conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO devices (node, kid, dev_cert, model, hw_rev, cert_serial, member,
                generation, role, member_cert, member_cert_serial, confirmed, dams,
                approved_ms, delivered_ms, confirmed_ms, last_seen_ms, removed_ms,
                removal_reason)
             VALUES (1, ?1, zeroblob(0), 0, 0, 0, 1, 1, 1, zeroblob(0), 1, 0, ?1,
                7, NULL, NULL, NULL, NULL, 0)",
            rusqlite::params![vec![0x33u8; 32]],
        )
        .unwrap();
    }

    #[test]
    fn migration_advances_a_used_v1_database() {
        let db = v1_db("migrate-used", |conn| {
            v1_key(conn, 4, &[0x11; 32], "active");
            v1_key(conn, 5, &[0x22; 32], "staged");
            v1_member(conn);
        });
        let mut store = SqliteSiteStore::open(&db).unwrap();
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.group_keys.len(), 2);
        assert_eq!(snapshot.gk_rotation, None);
        assert!(snapshot.gk_targets.is_empty());
        assert_eq!(
            snapshot.meta.get(META_HIGH_WATER).unwrap().as_slice(),
            5_u32.to_be_bytes()
        );
        // The store holds the exclusive lock: drop it before re-querying.
        drop(store);
        let version: Vec<u8> = rusqlite::Connection::open(&db)
            .unwrap()
            .query_row(
                "SELECT value FROM meta WHERE name = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_be_bytes());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn migration_leaves_a_fresh_v1_database_empty() {
        let db = v1_db("migrate-fresh", |_| {});
        let mut store = SqliteSiteStore::open(&db).unwrap();
        let snapshot = store.load().unwrap();
        assert!(snapshot.group_keys.is_empty());
        // No high-water mark: the authority mints epoch 1 on first open.
        assert!(!snapshot.meta.contains_key(META_HIGH_WATER));
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn migration_refuses_corrupt_key_tables() {
        // Two active keys.
        let db = v1_db("migrate-two-active", |conn| {
            v1_key(conn, 4, &[0x11; 32], "active");
            v1_key(conn, 5, &[0x22; 32], "active");
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
        // A zero key.
        let db = v1_db("migrate-zero", |conn| {
            v1_key(conn, 4, &[0; 32], "active");
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
        // Staged below active.
        let db = v1_db("migrate-order", |conn| {
            v1_key(conn, 5, &[0x11; 32], "active");
            v1_key(conn, 4, &[0x22; 32], "staged");
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
        // Staged without active, with member state around.
        let db = v1_db("migrate-no-active", |conn| {
            v1_key(conn, 5, &[0x22; 32], "staged");
            v1_member(conn);
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
        // A short key blob.
        let db = v1_db("migrate-short", |conn| {
            v1_key(conn, 4, &[0x11; 31], "active");
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
        // An unknown state.
        let db = v1_db("migrate-state", |conn| {
            v1_key(conn, 4, &[0x11; 32], "retired");
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn review_failed_migration_leaves_the_v1_schema_unchanged() {
        let db = v1_db("review-atomic-migration", |conn| {
            v1_key(conn, 4, &[0; 32], "active");
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let conn = rusqlite::Connection::open(&db).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('gk_rotation', 'gk_targets')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn review_missing_schema_version_in_used_database_is_rejected() {
        let db = temp_path("review-missing-version");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (name TEXT PRIMARY KEY, value BLOB NOT NULL);
             INSERT INTO meta (name, value) VALUES ('site_binding', x'01');",
        )
        .unwrap();
        drop(conn);
        std::fs::set_permissions(&db, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn review_v1_metadata_without_keys_does_not_migrate_as_fresh() {
        let db = v1_db("review-meta-without-keys", |conn| {
            conn.execute(
                "INSERT INTO meta (name, value) VALUES ('rs_epoch', ?1)",
                rusqlite::params![1_u32.to_be_bytes().to_vec()],
            )
            .unwrap();
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let conn = rusqlite::Connection::open(&db).unwrap();
        let version: Vec<u8> = conn
            .query_row(
                "SELECT value FROM meta WHERE name='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION_1.to_be_bytes());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn review_v1_negative_key_epoch_is_rejected() {
        let db = v1_db("review-negative-epoch", |conn| {
            conn.execute(
                "INSERT INTO group_keys (gk_epoch, gk, state, created_ms) VALUES (-1, ?1, 'active', 7)",
                rusqlite::params![vec![0x11_u8; 32]],
            )
            .unwrap();
        });
        assert!(SqliteSiteStore::open(&db).is_err());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn review_store_debug_redacts_group_keys_and_dams() {
        let key = GroupKeyRow {
            epoch: 3,
            key: [0xA5; 32],
            state: "active".into(),
            created_ms: 7,
        };
        let mut member = DeviceRow::default();
        member.node = 42;
        member.dams = [0xB6; 32];
        let snapshot = Snapshot {
            group_keys: vec![key],
            devices: vec![member],
            ..Snapshot::default()
        };
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("165, 165"), "GK leaked through Debug");
        assert!(!debug.contains("182, 182"), "DAMS leaked through Debug");
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn rotation_rows_and_targeted_deletes_round_trip() {
        let db = temp_path("rotation");
        let mut store = SqliteSiteStore::open(&db).unwrap();
        let rotation = RotationRow {
            operation_id: 9,
            from_epoch: 4,
            to_epoch: 5,
            cause: RotationCause::Removal,
            phase: RotationPhase::Staging,
            members_revision: 3,
            created_ms: 100,
            activated_ms: 0,
        };
        let targets = vec![
            TargetRow {
                rotation: 9,
                node: 0xA1,
                kid: [3; 32],
                generation: 1,
                state: TargetState::StagedAcked,
                confirmed_epoch: 5,
                confirmed_gkid: Some([7; 32]),
                last_contact_ms: Some(200),
            },
            TargetRow::fresh(9, 0xA2, [4; 32], 1),
        ];
        store
            .commit(&Batch {
                group_keys: vec![
                    GroupKeyRow {
                        epoch: 4,
                        key: [0x11; 32],
                        state: "active".into(),
                        created_ms: 50,
                    },
                    GroupKeyRow {
                        epoch: 5,
                        key: [0x22; 32],
                        state: "staged".into(),
                        created_ms: 100,
                    },
                ],
                gk_rotation: RotationWrite::Upsert(rotation.clone()),
                gk_targets: targets.clone(),
                ..Batch::default()
            })
            .unwrap();
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.gk_rotation, Some(rotation));
        assert_eq!(snapshot.gk_targets, targets);
        // A supersede deletes exactly the old staged row.
        store
            .commit(&Batch {
                group_keys_delete: vec![5],
                ..Batch::default()
            })
            .unwrap();
        let epochs: Vec<u32> = store
            .load()
            .unwrap()
            .group_keys
            .iter()
            .map(|g| g.epoch)
            .collect();
        assert_eq!(epochs, vec![4]);
        // Convergence deletes the rotation and its targets together.
        store
            .commit(&Batch {
                gk_rotation: RotationWrite::Delete,
                gk_targets_clear: true,
                ..Batch::default()
            })
            .unwrap();
        let snapshot = store.load().unwrap();
        assert_eq!(snapshot.gk_rotation, None);
        assert!(snapshot.gk_targets.is_empty());
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }
}
