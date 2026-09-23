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
//! | `meta` | name | schema version, site binding, policy, counters (rs_epoch, next serial, revision, ledger head) |
//! | `devices` | node | kid, DevCert, state member/removed, generation, role, MemberCert + serial, confirm state, DAMS, timestamps, removal |
//! | `ledger` | seq | approve/revoke entries in a SHA-256 hash chain |
//! | `rrs` | rs_epoch | every issued RRS1 object |
//! | `group_keys` | gk_epoch | GK bytes + state (latest two kept) |
//! | `docs` | (kind, key) | bookkeeping JSON: discovered devices, join requests, decisions, operations |
//!
//! Secrets at rest: DAMS and GK sit in the database file, protected by its
//! 0600 mode only — the 07 §3 "host-key sealing" is not implemented (no TPM
//! seam yet). The SAK is not here: it stays in its own 0600 key file behind
//! the `RootSigner` seam.

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 1;

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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerRow {
    pub seq: u64,
    /// "approve" or "revoke".
    pub kind: String,
    pub node: u64,
    pub kid: [u8; 32],
    pub generation: u32,
    /// SHA-256 of the MemberCert (approve) or of the RRS1 object (revoke).
    pub digest: [u8; 32],
    pub ms: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupKeyRow {
    pub epoch: u32,
    pub key: [u8; 32],
    /// "active" or "staged".
    pub state: String,
    pub created_ms: u64,
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

fn arr32(bytes: Vec<u8>, what: &str) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError(format!("site store: {what} is not 32 bytes")))
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
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "busy_timeout", 100)?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
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
             CREATE TABLE IF NOT EXISTS docs (
                kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (kind, key));",
        )?;
        let version: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM meta WHERE name='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match version {
            None => {
                conn.execute(
                    "INSERT INTO meta (name, value) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_be_bytes().to_vec()],
                )?;
            }
            Some(v) if v == SCHEMA_VERSION.to_be_bytes() => {}
            Some(_) => {
                return Err(StoreError(format!(
                    "site store {} has an unknown schema version",
                    path.display()
                )))
            }
        }
        Ok(Self { conn })
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
                epoch: epoch as u32,
                key: arr32(key, "gk")?,
                state,
                created_ms: u(created),
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
                    d.dams.to_vec(),
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
            tx.execute(
                "INSERT OR REPLACE INTO group_keys (gk_epoch, gk, state, created_ms) VALUES (?1, ?2, ?3, ?4)",
                params![i64::from(g.epoch), g.key.to_vec(), g.state, i(g.created_ms)],
            )?;
        }
        if let Some(below) = batch.group_keys_below {
            tx.execute(
                "DELETE FROM group_keys WHERE gk_epoch < ?1",
                params![i64::from(below)],
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
}
