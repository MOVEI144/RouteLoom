//! Durable office issuance ledger (P1-2/P2-4).
//!
//! Every `provision-identity` / `provision-devcert` run reserves its
//! (Device CA, NodeId, serial) slot in this ledger *before* minting any
//! key material, so the same slot can never be issued twice — not by a
//! re-run, not by a second terminal, not by a crash between keygen and
//! publish. The ledger is a JSONL file (default: `office-ledger.jsonl`
//! next to the `--ca-key` file, so one office directory shares one
//! ledger; `--ledger` overrides), guarded by a lockfile for concurrent
//! office terminals on the same machine.
//!
//! Uniqueness rules (checked under the lock, before anything is minted):
//! - a Device CA serial belongs to exactly one NodeId;
//! - a NodeId belongs to exactly one (Device CA, serial) — v1 never
//!   reissues a NodeId, so a used NodeId stays consumed even after the
//!   device is revoked and deprovisioned (reprovision takes a NEW NodeId).
//!
//! The *work* (default: the out directory; `--work-id` overrides) tells a
//! re-run of the same work apart from a duplicate issuance to another
//! device: the same work resumes (staging is reused, the published output
//! is adopted), any other work on a reserved slot refuses. A `reserved`
//! entry that never issues (abandoned work) is released explicitly with
//! `provision-ledger-release`; `issued`/`written` entries are never
//! released — they are the no-reissue history.

use routeloom_peercred::{try_lock_file_exclusive, unlock_file};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// A folded ledger entry: the latest known state of one issuance slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub device_ca_id: u64,
    pub node_id: u64,
    pub serial: u32,
    /// The issued device key id. `None` while merely reserved by the
    /// injected path (the key is minted after the reservation).
    pub kid: Option<[u8; 32]>,
    /// `sha256(devcert.cwt)` of the published DevCert. Recorded at
    /// `issued` time so `provision-confirm-written` can match the device
    /// receipt without the (possibly destroyed) output directory.
    pub devcert_sha256: Option<[u8; 32]>,
    pub work_id: String,
    pub out_dir: String,
    pub status: LedgerStatus,
    pub ts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerStatus {
    Reserved,
    Issued,
    Written,
}

impl LedgerStatus {
    pub(crate) fn name(self) -> &'static str {
        match self {
            LedgerStatus::Reserved => "reserved",
            LedgerStatus::Issued => "issued",
            LedgerStatus::Written => "written",
        }
    }

    fn parse(name: &str) -> Option<LedgerStatus> {
        match name {
            "reserved" => Some(LedgerStatus::Reserved),
            "issued" => Some(LedgerStatus::Issued),
            "written" => Some(LedgerStatus::Written),
            _ => None,
        }
    }
}

/// What `reserve` found for the requested slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// Freshly reserved by this call.
    New,
    /// The same work re-running (same slot, same work id).
    Resume(LedgerEntry),
}

/// One issuance slot: the (Device CA, NodeId, serial) triple the
/// ledger reserves at most once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IssueSlot {
    pub device_ca_id: u64,
    pub node_id: u64,
    pub serial: u32,
}

type FoldedLedger = std::collections::BTreeMap<IssueSlot, LedgerEntry>;

#[derive(Debug, Clone)]
pub struct OfficeLedger {
    path: PathBuf,
}

impl OfficeLedger {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        #[cfg(unix)]
        let mut opts = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new();
            o.mode(0o600);
            o
        };
        #[cfg(not(unix))]
        let mut opts = std::fs::OpenOptions::new();
        match opts.write(true).create_new(true).open(path) {
            Ok(file) => {
                file.sync_all()?;
                sync_parent(path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let canonical = std::fs::canonicalize(path)?;
        let metadata = std::fs::metadata(&canonical)?;
        if !metadata.is_file() {
            return Err("office ledger path is not a regular file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err("office ledger must not have hard-link aliases".into());
            }
        }
        Ok(OfficeLedger { path: canonical })
    }

    /// Serialize concurrent runs of the same work (same staging
    /// directory): held across stage → publish. Always taken outside
    /// the ledger lock (the ledger ops take it briefly inside), so the
    /// nesting never deadlocks.
    pub(crate) fn lock_work(staging: &Path) -> Result<WorkGuard, Box<dyn std::error::Error>> {
        let mut name = staging.as_os_str().to_owned();
        name.push(".lock");
        Ok(WorkGuard {
            _guard: Lockfile::acquire(&PathBuf::from(name))?,
        })
    }

    /// Fold the JSONL log to the latest entry per
    /// (device_ca_id, node_id, serial) slot. A torn last line (no
    /// trailing newline — a crashed writer) is ignored: the crashed
    /// reservation is void and the work resumes or re-reserves.
    pub fn entries(&self) -> Result<Vec<LedgerEntry>, Box<dyn std::error::Error>> {
        let _guard = Lockfile::acquire(&self.lock_path())?;
        let folded = Self::read_folded(&self.path)?;
        Ok(folded.into_values().collect())
    }

    /// Reserve a slot for a work, or confirm the same work's re-run.
    /// Refuses when the slot (or the NodeId, or the CA serial) belongs
    /// to another work.
    pub fn reserve(
        &self,
        slot: IssueSlot,
        kid: Option<[u8; 32]>,
        work_id: &str,
        out_dir: &str,
    ) -> Result<ReserveOutcome, Box<dyn std::error::Error>> {
        let _guard = Lockfile::acquire(&self.lock_path())?;
        let folded = Self::read_folded(&self.path)?;
        let IssueSlot {
            device_ca_id,
            node_id,
            serial,
        } = slot;
        for entry in folded.values() {
            let same_slot = entry.device_ca_id == device_ca_id
                && entry.node_id == node_id
                && entry.serial == serial;
            if !same_slot && (entry.work_id == work_id || entry.out_dir == out_dir) {
                return Err(format!(
                    "work {work_id} or output {out_dir} already belongs to node {:016x} serial {}",
                    entry.node_id, entry.serial
                )
                .into());
            }
            if entry.device_ca_id == device_ca_id
                && entry.serial == serial
                && entry.node_id != node_id
            {
                return Err(format!(
                    "serial {serial} of this Device CA is already reserved for node {:016x} (work {})",
                    entry.node_id, entry.work_id
                )
                .into());
            }
            if entry.node_id == node_id
                && (entry.device_ca_id != device_ca_id || entry.serial != serial)
            {
                return Err(format!(
                    "node {node_id:016x} is already reserved with serial {} (work {}); v1 never reissues a NodeId",
                    entry.serial, entry.work_id
                )
                .into());
            }
            if entry.device_ca_id == device_ca_id
                && entry.node_id == node_id
                && entry.serial == serial
            {
                if entry.work_id != work_id {
                    let state = match entry.status {
                        LedgerStatus::Reserved => "already reserved",
                        LedgerStatus::Issued | LedgerStatus::Written => "already issued",
                    };
                    return Err(format!(
                        "node {node_id:016x} serial {serial} is {state} under work {} (this work is {work_id}); re-run with the same --out-dir/--work-id to resume",
                        entry.work_id
                    )
                    .into());
                }
                if let (Some(want), Some(have)) = (kid, entry.kid) {
                    if want != have {
                        return Err(format!(
                            "node {node_id:016x} serial {serial} is reserved under work {work_id} for another device key; refusing a cross-device mixup"
                        )
                        .into());
                    }
                }
                if entry.out_dir != out_dir {
                    return Err(format!(
                        "work {work_id} reserved node {node_id:016x} serial {serial} for another directory ({})",
                        entry.out_dir
                    )
                    .into());
                }
                if entry.kid.is_none() && kid.is_some() && entry.status == LedgerStatus::Reserved {
                    let mut bound = entry.clone();
                    bound.kid = kid;
                    bound.ts = unix_secs();
                    Self::append(&self.path, &bound)?;
                    return Ok(ReserveOutcome::Resume(bound));
                }
                return Ok(ReserveOutcome::Resume(entry.clone()));
            }
        }
        let entry = LedgerEntry {
            device_ca_id,
            node_id,
            serial,
            kid,
            devcert_sha256: None,
            work_id: work_id.to_string(),
            out_dir: out_dir.to_string(),
            status: LedgerStatus::Reserved,
            ts: unix_secs(),
        };
        Self::append(&self.path, &entry)?;
        Ok(ReserveOutcome::New)
    }

    /// Record a publish. The kid and DevCert digest are re-read from the
    /// published output (not from RAM) by the caller. Idempotent for the
    /// same key; a different key for the same slot refuses loudly.
    pub fn mark_issued(
        &self,
        slot: IssueSlot,
        kid: [u8; 32],
        devcert_sha256: [u8; 32],
        work_id: &str,
        out_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _guard = Lockfile::acquire(&self.lock_path())?;
        let folded = Self::read_folded(&self.path)?;
        let IssueSlot {
            device_ca_id,
            node_id,
            serial,
        } = slot;
        let entry = folded
            .get(&slot)
            .ok_or_else(|| format!("node {node_id:016x} serial {serial} has no reservation"))?;
        if entry.work_id != work_id || entry.out_dir != out_dir {
            return Err(format!(
                    "node {node_id:016x} serial {serial} belongs to work {} at {}, not {work_id} at {out_dir}",
                    entry.work_id, entry.out_dir
                )
                .into());
        }
        if let Some(have) = entry.kid {
            if have != kid {
                return Err(format!(
                        "node {node_id:016x} serial {serial} was already issued for another device key; refusing a key swap"
                    )
                .into());
            }
        }
        if matches!(entry.status, LedgerStatus::Issued | LedgerStatus::Written) {
            if entry.devcert_sha256 != Some(devcert_sha256) {
                return Err(format!(
                    "node {node_id:016x} serial {serial} was issued with another DevCert digest"
                )
                .into());
            }
            return Ok(());
        }
        Self::append(
            &self.path,
            &LedgerEntry {
                device_ca_id,
                node_id,
                serial,
                kid: Some(kid),
                devcert_sha256: Some(devcert_sha256),
                work_id: work_id.to_string(),
                out_dir: out_dir.to_string(),
                status: LedgerStatus::Issued,
                ts: unix_secs(),
            },
        )?;
        Ok(())
    }

    /// Record a device write confirmation (`provision-confirm-written`).
    /// Only an issued slot can be confirmed; confirming twice is fine.
    pub fn mark_written(&self, slot: IssueSlot) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
        let _guard = Lockfile::acquire(&self.lock_path())?;
        let folded = Self::read_folded(&self.path)?;
        let Some(entry) = folded.get(&slot) else {
            return Err(format!(
                "node {:016x} serial {} has no ledger entry",
                slot.node_id, slot.serial
            )
            .into());
        };
        let (node_id, serial) = (slot.node_id, slot.serial);
        if matches!(entry.status, LedgerStatus::Reserved) {
            return Err(format!(
                "node {node_id:016x} serial {serial} was never issued; confirm a publish, not a reservation"
            )
            .into());
        }
        if matches!(entry.status, LedgerStatus::Written) {
            return Ok(entry.clone());
        }
        let mut confirmed = entry.clone();
        confirmed.status = LedgerStatus::Written;
        confirmed.ts = unix_secs();
        Self::append(&self.path, &confirmed)?;
        Ok(confirmed)
    }

    /// Drop a `reserved` entry (abandoned work) so the slot can be taken
    /// by another work. Only the owning work can release, and only while
    /// still reserved: issued history is never released.
    pub fn release(
        &self,
        node_id: u64,
        serial: u32,
        work_id: &str,
    ) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
        let candidate = self
            .entries()?
            .into_iter()
            .find(|entry| entry.node_id == node_id && entry.serial == serial)
            .ok_or_else(|| format!("node {node_id:016x} serial {serial} has no ledger entry"))?;
        if candidate.work_id != work_id {
            return Err(format!(
                "node {node_id:016x} serial {serial} belongs to work {}, not {work_id}",
                candidate.work_id
            )
            .into());
        }
        let staging = staging_dir(Path::new(&candidate.out_dir), work_id);
        let _work = Self::lock_work(&staging)?;
        let _guard = Lockfile::acquire(&self.lock_path())?;
        let folded = Self::read_folded(&self.path)?;
        let key = folded
            .keys()
            .find(|slot| slot.node_id == node_id && slot.serial == serial)
            .copied();
        let Some(key) = key else {
            return Err(format!("node {node_id:016x} serial {serial} has no ledger entry").into());
        };
        let entry = &folded[&key];
        if entry.work_id != work_id {
            return Err(format!(
                "node {node_id:016x} serial {serial} belongs to work {}, not {work_id}",
                entry.work_id
            )
            .into());
        }
        if !matches!(entry.status, LedgerStatus::Reserved) {
            return Err(format!(
                "node {node_id:016x} serial {serial} is already issued; issued history is never released"
            )
            .into());
        }
        if entry.kid.is_some() {
            return Err(format!(
                "node {node_id:016x} serial {serial} already has a bound device key; use a new NodeId"
            )
            .into());
        }
        if entry.out_dir != candidate.out_dir {
            return Err("office ledger changed during release".into());
        }
        require_absent(Path::new(&entry.out_dir))?;
        require_absent(&staging)?;
        require_absent(&staging_key_file(&staging))?;
        let released = entry.clone();
        Self::rewrite_without(&self.path, &key)?;
        Ok(released)
    }

    fn lock_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".lock");
        PathBuf::from(name)
    }

    fn read_folded(path: &Path) -> Result<FoldedLedger, Box<dyn std::error::Error>> {
        let text = Self::read_committed(path)?;
        let mut folded = FoldedLedger::new();
        for line in text.split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            let entry = parse_entry(line)?;
            let slot = IssueSlot {
                device_ca_id: entry.device_ca_id,
                node_id: entry.node_id,
                serial: entry.serial,
            };
            if let Some(previous) = folded.get(&slot) {
                let valid_step = matches!(
                    (previous.status, entry.status),
                    (LedgerStatus::Reserved, LedgerStatus::Reserved)
                        if previous.kid.is_none() && entry.kid.is_some()
                ) || matches!(
                    (previous.status, entry.status),
                    (LedgerStatus::Reserved, LedgerStatus::Issued)
                        | (LedgerStatus::Issued, LedgerStatus::Written)
                );
                if !valid_step
                    || previous.work_id != entry.work_id
                    || previous.out_dir != entry.out_dir
                    || (previous.kid.is_some() && previous.kid != entry.kid)
                    || (previous.devcert_sha256.is_some()
                        && previous.devcert_sha256 != entry.devcert_sha256)
                {
                    return Err("office ledger has an inconsistent state transition".into());
                }
            }
            folded.insert(slot, entry);
        }
        Ok(folded)
    }

    fn append(path: &Path, entry: &LedgerEntry) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
        let line = format_entry(entry);
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    fn read_committed(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        // A crashed append is void only when it lacks the newline. Remove
        // its bytes before the next append, under the ledger lock.
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            let committed = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |p| p + 1);
            file.set_len(committed as u64)?;
            file.sync_all()?;
            bytes.truncate(committed);
        }
        Ok(String::from_utf8(bytes)?)
    }

    fn rewrite_without(path: &Path, drop: &IssueSlot) -> Result<(), Box<dyn std::error::Error>> {
        let text = Self::read_committed(path)?;
        let tmp = format!("{}.tmp-{}", path.display(), std::process::id());
        // The ledger lock excludes a live writer; a leftover temporary
        // file can only be from an interrupted rewrite.
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut kept = String::new();
        for line in text.split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            let entry = parse_entry(line)?;
            let slot = IssueSlot {
                device_ca_id: entry.device_ca_id,
                node_id: entry.node_id,
                serial: entry.serial,
            };
            if slot != *drop {
                kept.push_str(line);
                kept.push('\n');
            }
        }
        #[cfg(unix)]
        let mut opts = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new();
            o.mode(0o600);
            o
        };
        #[cfg(not(unix))]
        let mut opts = std::fs::OpenOptions::new();
        let mut file = opts.write(true).create_new(true).open(&tmp)?;
        file.write_all(kept.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        sync_parent(path)?;
        Ok(())
    }
}

fn require_absent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(format!(
            "{} exists; inspect and securely remove work artifacts before releasing the reservation",
            path.display()
        )
        .into()),
        Err(e) => Err(e.into()),
    }
}

fn sync_parent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_u64(text: &str) -> Option<u64> {
    if text.len() != 16 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(text, 16).ok()
}

fn hex_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in text.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

fn parse_entry(line: &str) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
    let json = routeloom_json::parse(line).map_err(|e| format!("office ledger is corrupt: {e}"))?;
    let version = json.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != 1 {
        // Forward-compatible: a newer writer's entry is unreadable here.
        // Refusing is safer than folding it away.
        return Err(
            "office ledger has an entry this routeloomctl cannot read (newer format)".into(),
        );
    }
    let field = |name: &str| {
        json.get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("office ledger entry lacks {name}"))
    };
    let opt_hex = |name: &str| -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
        match json.get(name).and_then(|v| v.as_str()) {
            None => Ok(None),
            Some("") => Ok(None),
            Some(text) => hex_32(text)
                .map(Some)
                .ok_or_else(|| format!("office ledger entry has a bad {name}").into()),
        }
    };
    let device_ca_id =
        hex_u64(&field("device_ca_id")?).ok_or("office ledger entry has a bad device_ca_id")?;
    let node_id = hex_u64(&field("node_id")?).ok_or("office ledger entry has a bad node_id")?;
    let serial = json
        .get("serial")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("office ledger entry has a bad serial")?;
    let status = json
        .get("status")
        .and_then(|v| v.as_str())
        .and_then(LedgerStatus::parse)
        .ok_or("office ledger entry has a bad status")?;
    let kid = opt_hex("kid")?;
    let devcert_sha256 = opt_hex("devcert_sha256")?;
    if (status == LedgerStatus::Reserved && devcert_sha256.is_some())
        || (status != LedgerStatus::Reserved && (kid.is_none() || devcert_sha256.is_none()))
    {
        return Err("office ledger entry has incomplete issuance fields".into());
    }
    Ok(LedgerEntry {
        device_ca_id,
        node_id,
        serial,
        kid,
        devcert_sha256,
        work_id: field("work_id")?,
        out_dir: field("out_dir")?,
        status,
        ts: json.get("ts").and_then(|v| v.as_u64()).unwrap_or(0),
    })
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn format_entry(entry: &LedgerEntry) -> String {
    let kid = entry
        .kid
        .map(|k| format!("\"{}\"", hex_encode(&k)))
        .unwrap_or_else(|| "\"\"".to_string());
    let digest = entry
        .devcert_sha256
        .map(|d| format!("\"{}\"", hex_encode(&d)))
        .unwrap_or_else(|| "\"\"".to_string());
    format!(
        "{{\"v\":1,\"device_ca_id\":\"{:016x}\",\"node_id\":\"{:016x}\",\"serial\":{},\"kid\":{},\"devcert_sha256\":{},\"work_id\":\"{}\",\"out_dir\":\"{}\",\"status\":\"{}\",\"ts\":{}}}",
        entry.device_ca_id,
        entry.node_id,
        entry.serial,
        kid,
        digest,
        json_escape(&entry.work_id),
        json_escape(&entry.out_dir),
        entry.status.name(),
        entry.ts,
    )
}

/// The default work id: the out directory as an absolute,
/// lexically-normalized path, so spellings of the same directory
/// (`dev`, `./dev`) resume the same work.
pub fn default_work_id(out_dir: &Path) -> String {
    let absolute = if out_dir.is_absolute() {
        out_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(out_dir)
    };
    let mut parts: Vec<String> = Vec::new();
    for part in absolute.components() {
        use std::path::Component;
        match part {
            Component::RootDir => parts.push(String::new()),
            Component::CurDir => {}
            Component::ParentDir => match parts.last().map(String::as_str) {
                Some("") => {}
                Some("..") | None => parts.push("..".to_string()),
                Some(_) => {
                    parts.pop();
                }
            },
            Component::Normal(text) => parts.push(text.to_string_lossy().into_owned()),
            Component::Prefix(prefix) => {
                parts.push(prefix.as_os_str().to_string_lossy().into_owned())
            }
        }
    }
    if parts.first().map(String::as_str) == Some("") {
        format!("/{}", parts[1..].join("/"))
    } else {
        parts.join("/")
    }
}

/// The staging directory for a work: a sibling of the out directory on
/// the same filesystem (so the publish is one atomic rename), tagged
/// with the work id so two works never share staging.
pub fn staging_dir(out_dir: &Path, work_id: &str) -> PathBuf {
    let digest = routeloom_provision::sha256::sha256(work_id.as_bytes());
    let tag = hex_encode(&digest[..4]);
    let mut name = out_dir.as_os_str().to_owned();
    name.push(format!(".staging-{tag}"));
    PathBuf::from(name)
}

pub fn staging_key_file(staging: &Path) -> PathBuf {
    let mut name = staging.as_os_str().to_owned();
    name.push(".key");
    PathBuf::from(name)
}

/// Held across one work's stage → publish; dropping releases.
pub(crate) struct WorkGuard {
    _guard: Lockfile,
}

/// Exclusive kernel lock on a persistent lockfile. The kernel releases it
/// when a process exits; retaining the file preserves its inode for every
/// office terminal, including after a crash.
struct Lockfile {
    _file: std::fs::File,
}

impl Lockfile {
    fn acquire(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        #[cfg(unix)]
        let mut opts = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new();
            o.mode(0o600);
            o
        };
        #[cfg(not(unix))]
        let mut opts = std::fs::OpenOptions::new();
        let file = opts
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match try_lock_file_exclusive(&file) {
                Ok(true) => return Ok(Lockfile { _file: file }),
                Ok(false) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "office ledger is locked by another process ({}); refusing to issue blind",
                            path.display()
                        )
                        .into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl Drop for Lockfile {
    fn drop(&mut self) {
        let _ = unlock_file(&self._file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_normalization_stays_under_root() {
        assert_eq!(default_work_id(Path::new("/../tmp/issued")), "/tmp/issued");
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rl-ctl-ledger-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn slot(device_ca_id: u64, node_id: u64, serial: u32) -> IssueSlot {
        IssueSlot {
            device_ca_id,
            node_id,
            serial,
        }
    }

    #[test]
    fn reserve_refuses_duplicates_and_resumes_same_work() {
        let dir = scratch("duplicates");
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        let slot_a = slot(0x0DCA_0000_0000_0001, 0x00A1_0000_0000_1234, 90211);
        assert_eq!(
            ledger.reserve(slot_a, None, "work-a", "/tmp/a").unwrap(),
            ReserveOutcome::New
        );
        // Same slot, another work: refused.
        assert!(ledger.reserve(slot_a, None, "work-b", "/tmp/b").is_err());
        // Same node, another serial: refused (no NodeId reissue).
        assert!(ledger
            .reserve(
                slot(0x0DCA_0000_0000_0001, 0x00A1_0000_0000_1234, 90212),
                None,
                "work-c",
                "/tmp/c",
            )
            .is_err());
        // Same CA serial, another node: refused.
        assert!(ledger
            .reserve(
                slot(0x0DCA_0000_0000_0001, 0x00A1_0000_0000_9999, 90211),
                None,
                "work-d",
                "/tmp/d",
            )
            .is_err());
        // Same work re-running: resumes.
        match ledger.reserve(slot_a, None, "work-a", "/tmp/a").unwrap() {
            ReserveOutcome::Resume(entry) => assert_eq!(entry.status, LedgerStatus::Reserved),
            ReserveOutcome::New => panic!("same work must resume"),
        }
        // Same work, retargeted at another directory: refused.
        assert!(ledger
            .reserve(slot_a, None, "work-a", "/tmp/elsewhere")
            .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn torn_tail_is_void_and_lock_is_reentrant_across_calls() {
        let dir = scratch("torn");
        let path = dir.join("office-ledger.jsonl");
        let ledger = OfficeLedger::open(&path).unwrap();
        ledger
            .reserve(
                slot(0x0DCA_0000_0000_0001, 0x00A1_0000_0000_1234, 90211),
                None,
                "work-a",
                "/tmp/a",
            )
            .unwrap();
        assert_eq!(ledger.entries().unwrap().len(), 1);
        // A crashed append (no trailing newline) never landed.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file
            .write_all(
                br#"{"v":1,"device_ca_id":"0dca000000000001","node_id":"00a1000000009999","serial":90212,"kid":"","devcert_sha256":"","work_id":"crashed","out_dir":"/tmp/x","status":"reserved","ts":0}"#,
            )
            .unwrap();
        drop(file);
        assert_eq!(ledger.entries().unwrap().len(), 1);
        // ... so the slot is still free for a real work.
        assert_eq!(
            ledger
                .reserve(
                    slot(0x0DCA_0000_0000_0001, 0x00A1_0000_0000_9999, 90212),
                    None,
                    "work-b",
                    "/tmp/b",
                )
                .unwrap(),
            ReserveOutcome::New
        );
        assert_eq!(ledger.entries().unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unreadable_ledger_never_looks_empty() {
        let dir = scratch("unreadable");
        let path = dir.join("office-ledger.jsonl");
        std::fs::create_dir(&path).unwrap();
        assert!(OfficeLedger::open(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn issuance_requires_reservation_and_immutable_digest() {
        let dir = scratch("issued-integrity");
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        let slot_a = slot(1, 2, 3);
        assert!(ledger
            .mark_issued(slot_a, [1; 32], [2; 32], "work", "/tmp/work")
            .is_err());
        ledger.reserve(slot_a, None, "work", "/tmp/work").unwrap();
        ledger
            .mark_issued(slot_a, [1; 32], [2; 32], "work", "/tmp/work")
            .unwrap();
        assert!(ledger
            .mark_issued(slot_a, [1; 32], [3; 32], "work", "/tmp/work")
            .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lockfile_respects_an_existing_kernel_lock() {
        let dir = scratch("kernel-lock");
        let path = dir.join("ledger.lock");
        std::fs::write(&path, b"99999999").unwrap();
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(try_lock_file_exclusive(&held).unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            let guard = Lockfile::acquire(&path).unwrap();
            tx.send(()).unwrap();
            drop(guard);
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err());
        unlock_file(&held).unwrap();
        rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        contender.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn release_cannot_overtake_publication() {
        let dir = scratch("release-publish");
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        let out = dir.join("device");
        let work = "work";
        let slot_a = slot(1, 2, 3);
        ledger
            .reserve(slot_a, None, work, out.to_str().unwrap())
            .unwrap();
        let guard = OfficeLedger::lock_work(&staging_dir(&out, work)).unwrap();
        let contender = ledger.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            tx.send(contender.release(2, 3, work).is_err()).unwrap();
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err());
        std::fs::create_dir(&out).unwrap();
        drop(guard);
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
        thread.join().unwrap();
        assert_eq!(ledger.entries().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_bound_device_key_burns_the_reservation() {
        let dir = scratch("bound-key");
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        let slot_a = slot(1, 2, 3);
        ledger
            .reserve(slot_a, None, "work", "/tmp/bound-work")
            .unwrap();
        ledger
            .reserve(slot_a, Some([7; 32]), "work", "/tmp/bound-work")
            .unwrap();
        assert_eq!(ledger.entries().unwrap()[0].kid, Some([7; 32]));
        assert!(ledger.release(2, 3, "work").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn ledger_aliases_share_one_lock() {
        let dir = scratch("alias-lock");
        let real = dir.join("office-ledger.jsonl");
        let first = OfficeLedger::open(&real).unwrap();
        let alias = dir.join("alias.jsonl");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let second = OfficeLedger::open(&alias).unwrap();
        assert_eq!(first.lock_path(), second.lock_path());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn complete_but_inconsistent_ledger_line_is_corruption() {
        let dir = scratch("malformed-issued");
        let path = dir.join("office-ledger.jsonl");
        let ledger = OfficeLedger::open(&path).unwrap();
        let slot_a = slot(1, 2, 3);
        ledger.reserve(slot_a, None, "work", "/tmp/work").unwrap();
        let mut malformed = ledger.entries().unwrap().remove(0);
        malformed.status = LedgerStatus::Issued;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(format!("{}\n", format_entry(&malformed)).as_bytes())
            .unwrap();
        file.sync_all().unwrap();
        assert!(ledger.entries().is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn one_work_and_output_directory_cannot_claim_two_slots() {
        let dir = scratch("work-scope");
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        ledger
            .reserve(slot(1, 2, 3), None, "work-a", "/tmp/a")
            .unwrap();
        assert!(ledger
            .reserve(slot(1, 4, 5), None, "work-a", "/tmp/b")
            .is_err());
        assert!(ledger
            .reserve(slot(1, 4, 5), None, "work-b", "/tmp/a")
            .is_err());
        assert_eq!(ledger.entries().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn release_drops_reserved_only() {
        let dir = scratch("release");
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        let slot_a = slot(0x0DCA_0000_0000_0001, 0x00A1_0000_0000_1234, 90211);
        ledger.reserve(slot_a, None, "work-a", "/tmp/a").unwrap();
        // Another work cannot release.
        assert!(ledger
            .release(0x00A1_0000_0000_1234, 90211, "work-b")
            .is_err());
        let released = ledger
            .release(0x00A1_0000_0000_1234, 90211, "work-a")
            .unwrap();
        assert_eq!(released.status, LedgerStatus::Reserved);
        assert!(ledger.entries().unwrap().is_empty());
        // The slot is free again.
        assert_eq!(
            ledger.reserve(slot_a, None, "work-b", "/tmp/b").unwrap(),
            ReserveOutcome::New
        );
        // ... but never once issued.
        ledger
            .mark_issued(slot_a, [0x22; 32], [0x33; 32], "work-b", "/tmp/b")
            .unwrap();
        assert!(ledger
            .release(0x00A1_0000_0000_1234, 90211, "work-b")
            .is_err());
        // mark_issued with another key refuses; with the same key it is
        // idempotent.
        assert!(ledger
            .mark_issued(slot_a, [0x44; 32], [0x55; 32], "work-b", "/tmp/b")
            .is_err());
        ledger
            .mark_issued(slot_a, [0x22; 32], [0x33; 32], "work-b", "/tmp/b")
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
