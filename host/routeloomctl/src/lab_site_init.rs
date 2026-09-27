//! Create a private, per-site development authority. A journal binds a
//! partial initialization to its original spec and keys across restarts.

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_json::Json;
use routeloom_provision::credential::credential_kid;
use routeloom_provision::sdkv1::cert::CERT_MAX;
use routeloom_provision::sdkv1::devca::{devcert_verify, DeviceCaSigner, FileDeviceCaSigner};
use routeloom_provision::sdkv1::siteca::{
    sitecert_issue, FileSiteCaSigner, SiteCaSigner, SiteCertProfile,
};
use routeloom_provision::sha256::sha256;
use zeroize::Zeroizing;

use routeloom_provision::signer::{
    fill_random, hex_encode, write_private_file, FileRootSigner, RootSigner,
};

use crate::{
    office_ledger::{LedgerStatus, OfficeLedger},
    opt_value,
};

type DynError = Box<dyn std::error::Error>;

fn id(value: Option<&Json>, name: &str) -> Result<u64, DynError> {
    let text = value
        .and_then(Json::as_str)
        .ok_or_else(|| format!("{name} requires 16 hex digits"))?;
    if text.len() != 16 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{name} requires 16 hex digits").into());
    }
    let n = u64::from_str_radix(text, 16)?;
    if n == 0 || n == u64::MAX {
        return Err(format!("{name} is reserved").into());
    }
    Ok(n)
}

fn private_dir(path: &Path) -> Result<(), DynError> {
    if path.exists() {
        return Err(format!("{} already exists", path.display()).into());
    }
    routeloom_peercred::create_private_dir_all(path)?;
    Ok(())
}

fn check_private(path: &Path, directory: bool) -> Result<(), DynError> {
    let meta = fs::symlink_metadata(path)?;
    if !(if directory {
        meta.file_type().is_dir()
    } else {
        meta.file_type().is_file()
    }) {
        return Err(format!("{} must not be a symlink", path.display()).into());
    }
    if directory {
        routeloom_peercred::verify_private_dir_perms(path)?;
    } else {
        routeloom_peercred::verify_private_file_perms(path)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), DynError> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(windows)]
    let _ = path; // NTFS flushes each newly written file; directories are not openable as File.
    Ok(())
}

fn sync_file(path: &Path) -> Result<(), DynError> {
    fs::OpenOptions::new().write(true).open(path)?.sync_all()?;
    Ok(())
}

fn journal_record(
    path: &Path,
    name: &str,
    fingerprint: &[u8; 32],
    journal: &mut String,
) -> Result<(), DynError> {
    use std::io::Write;
    let entry = format!("{name}:{}\n", hex_encode(fingerprint));
    if journal
        .lines()
        .any(|line| line.starts_with(&format!("{name}:")))
    {
        if !journal.lines().any(|line| line == entry.trim_end()) {
            return Err(format!("{name} disagrees with initialization journal").into());
        }
        return Ok(());
    }
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(entry.as_bytes())?;
    file.sync_all()?;
    journal.push_str(&entry);
    Ok(())
}

fn file_exists(path: &Path) -> Result<bool, DynError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            check_private(path, false)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Import a written receipt from the office ledger, never a merely issued
/// DevCert. Restart the site daemon to load the next inventory revision.
pub fn inventory_import(args: &[String]) -> Result<(), DynError> {
    let mut site_dir = None;
    let mut ledger = None;
    let mut node = None;
    let mut role = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--site" => site_dir = Some(opt_value(&mut args, "--site")?),
            "--ledger" => ledger = Some(opt_value(&mut args, "--ledger")?),
            "--node" => node = Some(opt_value(&mut args, "--node")?),
            "--role" => role = Some(opt_value(&mut args, "--role")?),
            _ => return Err(format!("unknown lab-inventory-import option: {arg}").into()),
        }
    }
    let dir = PathBuf::from(site_dir.ok_or("--site required")?);
    let manifest_path = dir.join("lab-manifest.json");
    let inventory_path = dir.join("inventory.db");
    if manifest_path.is_symlink() || inventory_path.is_symlink() {
        return Err("symlink in lab site".into());
    }
    let manifest = routeloom_json::parse_bounded(&fs::read_to_string(manifest_path)?, 4)?;
    if manifest.get("purpose").and_then(Json::as_str) != Some("development")
        || manifest.get("format").and_then(Json::as_str) != Some("routeloom-lab-site-v1")
    {
        return Err("not a development site".into());
    }
    let site_id = id(manifest.get("site_id"), "site_id")?;
    let ca = FileDeviceCaSigner::load(&dir.join("keys/device-ca.key"))?;
    let fingerprint = manifest
        .get("device_ca_fingerprint")
        .and_then(Json::as_str)
        .ok_or("missing CA fingerprint")?;
    if fingerprint != hex_encode(&sha256(&ca.pubkey())) {
        return Err("Device CA does not match lab manifest".into());
    }
    let node = id(Some(&Json::String(node.ok_or("--node required")?)), "node")?;
    let role = match role.ok_or("--role required")?.as_str() {
        "endpoint" => 1u8,
        "relay" => 2,
        "gateway" => 4,
        _ => return Err("role must be endpoint, relay or gateway".into()),
    };
    if role == 4 {
        let config = routeloom_json::parse_bounded(
            &fs::read_to_string(dir.join("site-authority.json"))?,
            8,
        )?;
        let gateways = config
            .get("gateways")
            .and_then(Json::as_array)
            .ok_or("invalid gateway list")?;
        if !gateways
            .iter()
            .any(|g| id(Some(g), "gateway").ok() == Some(node))
        {
            return Err("gateway not configured for this site".into());
        }
    }
    let entries = OfficeLedger::open(Path::new(&ledger.ok_or("--ledger required")?))?.entries()?;
    let matched = entries
        .iter()
        .find(|entry| {
            entry.device_ca_id == ca.device_ca_id()
                && entry.node_id == node
                && entry.status == LedgerStatus::Written
        })
        .ok_or("no provision-confirm-written receipt for this site CA and NodeId")?;
    let kid = matched.kid.ok_or("written receipt lacks kid")?;
    let cert_path = Path::new(&matched.out_dir).join("devcert.cwt");
    if fs::metadata(&cert_path)?.len() > CERT_MAX as u64 {
        return Err("published DevCert exceeds protocol limit".into());
    }
    let cert = fs::read(&cert_path)?;
    if matched.devcert_sha256 != Some(sha256(&cert)) {
        return Err("published DevCert differs from written receipt".into());
    }
    let claims = devcert_verify(&cert, ca.device_ca_id(), &ca.pubkey())?;
    if claims.subject != node
        || claims.serial != matched.serial
        || credential_kid(&claims.pubkey) != kid
    {
        return Err("written receipt and site Device CA certificate disagree".into());
    }
    let mut db = rusqlite::Connection::open(inventory_path)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let site_text = format!("{site_id:016x}");
    let old: Option<(String, u8)> = {
        use rusqlite::OptionalExtension;
        tx.query_row(
            "SELECT kid,role FROM inventory WHERE site_id=?1 AND node=?2",
            [&site_text, &format!("{node:016x}")],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
    };
    if let Some((old_kid, old_role)) = old {
        if old_kid != hex_encode(&kid) || old_role != role {
            return Err("inventory NodeId already bound to another kid or role".into());
        }
    } else {
        let count: u32 = tx.query_row(
            "SELECT count(*) FROM inventory WHERE site_id=?1",
            [&site_text],
            |r| r.get(0),
        )?;
        if count >= 128 {
            return Err("lab inventory full".into());
        }
        tx.execute(
            "INSERT INTO inventory VALUES (?1,?2,?3,?4,1)",
            rusqlite::params![site_text, format!("{node:016x}"), hex_encode(&kid), role],
        )?;
        tx.execute(
            "UPDATE inventory_meta SET revision=revision+1 WHERE site_id=?1",
            [&site_text],
        )?;
    }
    tx.commit()?;
    println!(
        "{{\"site_id\":\"{site_id:016x}\",\"node\":\"{node:016x}\",\"kid\":\"{}\"}}",
        hex_encode(&kid)
    );
    Ok(())
}

pub fn command(args: &[String]) -> Result<(), DynError> {
    let mut spec = None;
    let mut out = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--spec" => spec = Some(opt_value(&mut args, "--spec")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            _ => return Err(format!("unknown lab-site-init option: {arg}").into()),
        }
    }
    let spec = fs::read_to_string(spec.ok_or("lab-site-init requires --spec FILE")?)?;
    let out = PathBuf::from(out.ok_or("lab-site-init requires --out DIR")?);
    let root = routeloom_json::parse_bounded(&spec, 4)?;
    for (key, _) in root.object_entries() {
        if !matches!(
            key.as_str(),
            "format"
                | "site_id"
                | "device_ca_id"
                | "site_ca_id"
                | "network_low32"
                | "channel"
                | "gateways"
        ) {
            return Err(format!("unknown lab site spec field: {key}").into());
        }
    }
    if root.get("format").and_then(Json::as_str) != Some("routeloom-lab-site-spec-v1") {
        return Err("invalid lab site spec format".into());
    }
    let site = id(root.get("site_id"), "site_id")?;
    let device_id = id(root.get("device_ca_id"), "device_ca_id")?;
    let ca_id = id(root.get("site_ca_id"), "site_ca_id")?;
    let network_text = root
        .get("network_low32")
        .and_then(Json::as_str)
        .ok_or("network_low32 required")?;
    if network_text.len() != 8 || !network_text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("network_low32 requires 8 hex digits".into());
    }
    let network_low32 = u32::from_str_radix(network_text, 16)?;
    if network_low32 == 0 {
        return Err("network_low32 is reserved".into());
    }
    let channel = root
        .get("channel")
        .and_then(Json::as_u64)
        .ok_or("channel required")?;
    if !(1..=14).contains(&channel) {
        return Err("channel must be 1..14".into());
    }
    let gateways = root
        .get("gateways")
        .and_then(Json::as_array)
        .ok_or("gateways required")?;
    if !(1..=4).contains(&gateways.len()) {
        return Err("1..4 gateways required".into());
    }
    let gateway_ids = gateways
        .iter()
        .map(|g| id(Some(g), "gateway"))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, gateway) in gateway_ids.iter().enumerate() {
        if gateway_ids[..i].contains(gateway) {
            return Err("duplicate gateway".into());
        }
    }
    let journal_path = out.join("lab-init.journal");
    let header = format!(
        "routeloom-lab-init-v1\nspec:{}\n",
        hex_encode(&sha256(spec.as_bytes()))
    );
    match fs::symlink_metadata(&out) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => private_dir(&out)?,
        Ok(_) => check_private(&out, true)?,
        Err(e) => return Err(e.into()),
    }
    let published_manifest = file_exists(&out.join("lab-manifest.json"))?;
    let mut journal = if file_exists(&journal_path)? {
        fs::read_to_string(&journal_path)?
    } else {
        if fs::read_dir(&out)?.next().is_some() {
            return Err("nonempty site directory without initialization journal".into());
        }
        write_private_file(&journal_path, header.as_bytes())?;
        sync_file(&journal_path)?;
        header.clone()
    };
    if journal.starts_with(&header) && !journal.ends_with('\n') {
        let complete_len = journal
            .rfind('\n')
            .ok_or("invalid initialization journal")?
            + 1;
        let file = fs::OpenOptions::new().write(true).open(&journal_path)?;
        file.set_len(complete_len as u64)?;
        file.sync_all()?;
        journal.truncate(complete_len);
    }
    if !journal.starts_with(&header) {
        return Err("initialization journal differs from spec".into());
    }
    if journal.lines().any(|line| line == "complete") {
        return Err("initialization journal differs from spec or site was completed".into());
    }
    let keys_dir = out.join("keys");
    match fs::symlink_metadata(&keys_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => private_dir(&keys_dir)?,
        Ok(_) => check_private(&keys_dir, true)?,
        Err(e) => return Err(e.into()),
    }
    let device_path = keys_dir.join("device-ca.key");
    let device_ca = if file_exists(&device_path)? {
        FileDeviceCaSigner::load(&device_path)?
    } else {
        if journal.contains("device-ca:") {
            return Err("recorded Device CA key is missing".into());
        }
        let key = FileDeviceCaSigner::generate(device_id)?;
        key.save(&device_path)?;
        key
    };
    if device_ca.device_ca_id() != device_id {
        return Err("Device CA id differs from spec".into());
    }
    sync_file(&device_path)?;
    sync_dir(&keys_dir)?;
    journal_record(
        &journal_path,
        "device-ca",
        &sha256(&device_ca.pubkey()),
        &mut journal,
    )?;
    let site_path = keys_dir.join("site-ca.key");
    let site_ca = if file_exists(&site_path)? {
        FileSiteCaSigner::load(&site_path)?
    } else {
        if journal.contains("site-ca:") {
            return Err("recorded Site CA key is missing".into());
        }
        let key = FileSiteCaSigner::generate(ca_id)?;
        key.save(&site_path)?;
        key
    };
    if site_ca.site_ca_id() != ca_id {
        return Err("Site CA id differs from spec".into());
    }
    sync_file(&site_path)?;
    sync_dir(&keys_dir)?;
    journal_record(
        &journal_path,
        "site-ca",
        &sha256(&site_ca.pubkey()),
        &mut journal,
    )?;
    let sak_path = out.join("sak.key");
    let sak = if file_exists(&sak_path)? {
        FileRootSigner::load(&sak_path)?
    } else {
        if journal.contains("sak:") {
            return Err("recorded SAK key is missing".into());
        }
        let key = FileRootSigner::generate(site)?;
        key.save(&sak_path)?;
        key
    };
    if sak.root_id() != site {
        return Err("SAK id differs from spec".into());
    }
    sync_file(&sak_path)?;
    sync_dir(&out)?;
    journal_record(
        &journal_path,
        "sak",
        &credential_kid(&sak.pubkey()),
        &mut journal,
    )?;
    let cert = sitecert_issue(
        &site_ca,
        site,
        &sak.pubkey(),
        &SiteCertProfile {
            network_low32,
            site_epoch: 1,
            serial: 1,
        },
    )?;
    // Both the raw secret and its encoded copy must be wiped on errors too.
    let usb_path = out.join("usb-dev-secret.key");
    let usb_hex = if file_exists(&usb_path)? {
        Zeroizing::new(fs::read_to_string(&usb_path)?)
    } else {
        if journal.contains("usb-secret:") {
            return Err("recorded USB secret is missing".into());
        }
        let mut usb_secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut usb_secret[..])?;
        let hex = Zeroizing::new(hex_encode(&usb_secret[..]));
        write_private_file(&usb_path, hex.as_bytes())?;
        hex
    };
    if usb_hex.len() != 64 || !usb_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("USB secret corrupt".into());
    }
    sync_file(&usb_path)?;
    sync_dir(&out)?;
    journal_record(
        &journal_path,
        "usb-secret",
        &sha256(usb_hex.as_bytes()),
        &mut journal,
    )?;
    let config = format!(
        "{{\"format\":\"routeloom-site-authority-v1\",\"site_cert_hex\":\"{}\",\"site_ca_pubkey_hex\":\"{}\",\"device_ca\":{{\"id\":\"{device_id:016x}\",\"pubkey_hex\":\"{}\"}},\"channel\":{channel},\"channel_epoch\":1,\"gateways\":[{}]}}",
        hex_encode(&cert), hex_encode(&site_ca.pubkey()), hex_encode(&device_ca.pubkey()),
        gateway_ids.iter().map(|n| format!("\"{n:016x}\"")).collect::<Vec<_>>().join(",")
    );
    let config_path = out.join("site-authority.json");
    if file_exists(&config_path)? {
        // The public config can be reconstructed from the journal-bound
        // keys when a write was interrupted; never replace a private key.
        if fs::read_to_string(&config_path)? != config {
            fs::write(&config_path, config.as_bytes())?;
        }
    } else {
        write_private_file(&config_path, config.as_bytes())?;
    }
    sync_file(&config_path)?;
    let manifest = format!(
        "{{\"format\":\"routeloom-lab-site-v1\",\"purpose\":\"development\",\"site_id\":\"{site:016x}\",\"site_ca_fingerprint\":\"{}\",\"device_ca_fingerprint\":\"{}\",\"sak_fingerprint\":\"{}\"}}",
        hex_encode(&sha256(&site_ca.pubkey())), hex_encode(&sha256(&device_ca.pubkey())), hex_encode(&credential_kid(&sak.pubkey()))
    );
    let inventory_path = out.join("inventory.db");
    let existing_inventory = file_exists(&inventory_path)?;
    if !existing_inventory {
        let file = routeloom_peercred::open_private_file_for_write(&inventory_path)?;
        file.sync_all()?;
    }
    let db = rusqlite::Connection::open(&inventory_path)?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS inventory_meta(site_id TEXT PRIMARY KEY, revision INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS inventory(site_id TEXT NOT NULL, node TEXT NOT NULL, kid TEXT NOT NULL, role INTEGER NOT NULL, completed INTEGER NOT NULL, PRIMARY KEY(site_id,node));")?;
    db.execute(
        "INSERT OR IGNORE INTO inventory_meta VALUES (?1, 0)",
        [format!("{site:016x}")],
    )?;
    let revision: u64 = db.query_row(
        "SELECT revision FROM inventory_meta WHERE site_id=?1",
        [format!("{site:016x}")],
        |r| r.get(0),
    )?;
    let count: u64 = db.query_row("SELECT count(*) FROM inventory", [], |r| r.get(0))?;
    if revision != 0 || count != 0 {
        return Err("partial site inventory is not empty".into());
    }
    drop(db);
    sync_file(&inventory_path)?;
    sync_dir(&out)?;
    // The manifest is the last published artifact. A crash between its
    // rename and the journal completion may only accept the same content.
    if published_manifest {
        if fs::read(out.join("lab-manifest.json"))? != manifest.as_bytes() {
            return Err("published manifest differs from initialization journal".into());
        }
    } else {
        let pending = out.join("lab-manifest.json.pending");
        if file_exists(&pending)? {
            fs::remove_file(&pending)?;
        }
        write_private_file(&pending, manifest.as_bytes())?;
        sync_file(&pending)?;
        fs::rename(&pending, out.join("lab-manifest.json"))?;
        sync_dir(&out)?;
    }
    use std::io::Write;
    let mut journal_file = fs::OpenOptions::new().append(true).open(&journal_path)?;
    journal_file.write_all(b"complete\n")?;
    journal_file.sync_all()?;
    println!("{{\"site_id\":\"{site:016x}\",\"purpose\":\"development\"}}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::office_ledger::IssueSlot;
    use routeloom_provision::credential::KeyLocation;
    use routeloom_provision::sdkv1::devca::{devcert_issue, DevCertProfile};
    use routeloom_provision::sdkv1::pop::{pop_sign, pop_verify};

    #[test]
    fn written_receipt_import_is_revisioned_and_issued_only_is_refused() {
        let parent = std::env::temp_dir().join(format!(
            "routeloom-lab-import-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        private_dir(&parent).unwrap();
        let spec = parent.join("spec.json");
        fs::write(&spec, r#"{"format":"routeloom-lab-site-spec-v1","site_id":"0123456789abcdef","device_ca_id":"1023456789abcdef","site_ca_id":"2023456789abcdef","network_low32":"12345678","channel":1,"gateways":["3023456789abcdef"]}"#).unwrap();
        let site = parent.join("site");
        command(&[
            "--spec".into(),
            spec.to_string_lossy().into_owned(),
            "--out".into(),
            site.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let ledger_path = parent.join("ledger.jsonl");
        let ledger = OfficeLedger::open(&ledger_path).unwrap();
        let slot = IssueSlot {
            device_ca_id: 0x1023_4567_89ab_cdef,
            node_id: 0x3023_4567_89ab_cdef,
            serial: 1,
        };
        let challenge = [8; 32];
        let pop = pop_sign(
            &[7; 32],
            slot.node_id,
            KeyLocation::NvsPlaintext,
            &challenge,
        )
        .unwrap();
        let device = pop_verify(&pop, slot.node_id, &challenge).unwrap();
        let kid = credential_kid(&device.pubkey());
        let ca = FileDeviceCaSigner::load(&site.join("keys/device-ca.key")).unwrap();
        let cert = devcert_issue(
            &ca,
            &device,
            &DevCertProfile {
                serial: slot.serial,
                ..DevCertProfile::default()
            },
        )
        .unwrap();
        let out = parent.join("issued");
        private_dir(&out).unwrap();
        fs::write(out.join("devcert.cwt"), &cert).unwrap();
        let out_text = out.to_str().unwrap();
        ledger.reserve(slot, Some(kid), "work", out_text).unwrap();
        ledger
            .mark_issued(slot, kid, sha256(&cert), "work", out_text)
            .unwrap();
        let args = vec![
            "--site".into(),
            site.to_string_lossy().into_owned(),
            "--ledger".into(),
            ledger_path.to_string_lossy().into_owned(),
            "--node".into(),
            format!("{:016x}", slot.node_id),
            "--role".into(),
            "gateway".into(),
        ];
        assert!(inventory_import(&args).is_err());
        ledger.mark_written(slot).unwrap();
        inventory_import(&args).unwrap();
        inventory_import(&args).unwrap();
        let db = rusqlite::Connection::open(site.join("inventory.db")).unwrap();
        let (revision, count): (u64, u64) = (
            db.query_row("SELECT revision FROM inventory_meta", [], |r| r.get(0))
                .unwrap(),
            db.query_row(
                "SELECT count(*) FROM inventory WHERE completed=1",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        );
        assert_eq!((revision, count), (1, 1));
        drop(db);
        let other_node = slot.node_id + 1;
        let other_slot = IssueSlot {
            node_id: other_node,
            serial: 2,
            ..slot
        };
        let pop = pop_sign(&[9; 32], other_node, KeyLocation::NvsPlaintext, &challenge).unwrap();
        let device = pop_verify(&pop, other_node, &challenge).unwrap();
        let other_kid = credential_kid(&device.pubkey());
        let other_ca = FileDeviceCaSigner::from_secret(slot.device_ca_id, &[10; 32]).unwrap();
        let other_cert = devcert_issue(
            &other_ca,
            &device,
            &DevCertProfile {
                serial: other_slot.serial,
                ..DevCertProfile::default()
            },
        )
        .unwrap();
        let other_out = parent.join("other-issued");
        private_dir(&other_out).unwrap();
        fs::write(other_out.join("devcert.cwt"), &other_cert).unwrap();
        let other_text = other_out.to_str().unwrap();
        ledger
            .reserve(other_slot, Some(other_kid), "other-work", other_text)
            .unwrap();
        ledger
            .mark_issued(
                other_slot,
                other_kid,
                sha256(&other_cert),
                "other-work",
                other_text,
            )
            .unwrap();
        ledger.mark_written(other_slot).unwrap();
        let other_args = [
            "--site".into(),
            site.to_string_lossy().into_owned(),
            "--ledger".into(),
            ledger_path.to_string_lossy().into_owned(),
            "--node".into(),
            format!("{other_node:016x}"),
            "--role".into(),
            "endpoint".into(),
        ];
        assert!(inventory_import(&other_args).is_err());
        let _ = fs::remove_dir_all(parent);
    }
}
