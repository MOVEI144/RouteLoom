//! `--site-authority DIR`: the Site Authority's directory (07 §3).
//!
//! ```text
//! DIR/site-authority.json   configuration (below), read at start
//! DIR/sak.key               SAK, `routeloom-root-key-v1` (FileRootSigner, 0600,
//!                           root_id = site_id) — development custody only
//! DIR/site.db               the store (created 0600 on first start)
//! ```
//!
//! ```json
//! {
//!   "format": "routeloom-site-authority-v1",
//!   "site_cert_hex": "d28443a10126a0…",          // SiteCert (Site CA → SAK)
//!   "site_ca_pubkey_hex": "…128 hex…",           // optional: verify the SiteCert at start
//!   "device_ca": {"id": "0dca000000000001", "pubkey_hex": "…128 hex…"},
//!   "channel": 1, "channel_epoch": 1,
//!   "gateways": ["00a1000000000001"]             // 1..4, announced in the SitePackage
//! }
//! ```
//!
//! Issuing the SiteCert is an HQ step (`routeloomctl site-cert`, P7-2); a development directory is assembled with the office tooling's
//! key files and that command.

use std::path::Path;

use routeloom_json::Json;
use routeloom_provision::signer::hex_encode;
use routeloom_provision::signer::{FileRootSigner, RootSigner, FILE_KEY_CUSTODY_WARNING};

use super::records::{parse_h16, parse_hex};
use super::store::SqliteSiteStore;
use super::{LabBinding, LabDevice, SiteAuthority, SitePurpose, SiteSetup};
use rusqlite::Connection;

pub const CONFIG_FORMAT: &str = "routeloom-site-authority-v1";
pub const CONFIG_FILE: &str = "site-authority.json";
pub const SAK_FILE: &str = "sak.key";
pub const STORE_FILE: &str = "site.db";

fn pubkey(json: Option<&Json>, what: &str) -> Result<[u8; 64], String> {
    json.and_then(Json::as_str)
        .and_then(|t| parse_hex(&t.to_ascii_lowercase(), 64))
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("{CONFIG_FILE}: {what} must be 128 hex characters"))
}

/// Parses `site-authority.json` (unknown fields are refused).
pub fn parse_setup(text: &str) -> Result<SiteSetup, String> {
    let root = routeloom_json::parse_bounded(text, 8).map_err(|e| format!("{CONFIG_FILE}: {e}"))?;
    for (key, _) in root.object_entries() {
        if !matches!(
            key.as_str(),
            "format"
                | "site_cert_hex"
                | "site_ca_pubkey_hex"
                | "device_ca"
                | "channel"
                | "channel_epoch"
                | "gateways"
        ) {
            return Err(format!("{CONFIG_FILE}: unknown field \"{key}\""));
        }
    }
    if root.get("format").and_then(Json::as_str) != Some(CONFIG_FORMAT) {
        return Err(format!("{CONFIG_FILE}: format must be \"{CONFIG_FORMAT}\""));
    }
    let site_cert = root
        .get("site_cert_hex")
        .and_then(Json::as_str)
        .and_then(|t| parse_hex(&t.to_ascii_lowercase(), t.len() / 2))
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{CONFIG_FILE}: site_cert_hex must be hex"))?;
    let site_ca_pubkey = match root.get("site_ca_pubkey_hex") {
        None => None,
        value => Some(pubkey(value, "site_ca_pubkey_hex")?),
    };
    let device_ca = root
        .get("device_ca")
        .ok_or_else(|| format!("{CONFIG_FILE}: device_ca is required"))?;
    let device_ca_id = device_ca
        .get("id")
        .and_then(Json::as_str)
        .and_then(|t| parse_h16(&t.to_ascii_lowercase()))
        .ok_or_else(|| format!("{CONFIG_FILE}: device_ca.id must be 16 hex"))?;
    let device_ca_pubkey = pubkey(device_ca.get("pubkey_hex"), "device_ca.pubkey_hex")?;
    let channel = root
        .get("channel")
        .and_then(Json::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(|| format!("{CONFIG_FILE}: channel must be 1..14"))?;
    let channel_epoch = root
        .get("channel_epoch")
        .and_then(Json::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| format!("{CONFIG_FILE}: channel_epoch must be a u32"))?;
    let gateways = root
        .get("gateways")
        .and_then(Json::as_array)
        .ok_or_else(|| format!("{CONFIG_FILE}: gateways must be an array"))?
        .iter()
        .map(|g| g.as_str().and_then(|t| parse_h16(&t.to_ascii_lowercase())))
        .collect::<Option<Vec<u64>>>()
        .ok_or_else(|| format!("{CONFIG_FILE}: gateways must be 16-hex node ids"))?;
    Ok(SiteSetup {
        site_cert,
        site_ca_pubkey,
        device_ca_id,
        device_ca_pubkey,
        channel,
        channel_epoch,
        gateways,
        lab: None,
        purpose: SitePurpose::Import,
    })
}

/// Opens the authority of `dir` (see the module docs).
pub fn open_dir(dir: &Path, now_ms: u64) -> Result<SiteAuthority, String> {
    let config = std::fs::read_to_string(dir.join(CONFIG_FILE))
        .map_err(|e| format!("cannot read {}: {e}", dir.join(CONFIG_FILE).display()))?;
    let mut setup = parse_setup(&config)?;
    let lab_metadata = match std::fs::symlink_metadata(dir.join("lab-manifest.json")) {
        Ok(metadata) => Some(metadata),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot inspect lab manifest: {e}")),
    };
    let mut manifest_site_id = None;
    if let Some(metadata) = lab_metadata {
        if !metadata.file_type().is_file() {
            return Err("lab manifest must be a regular file, not a symlink".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("lab manifest must be private (0600)".into());
            }
        }
        let text = std::fs::read_to_string(dir.join("lab-manifest.json"))
            .map_err(|e| format!("lab manifest: {e}"))?;
        let manifest =
            routeloom_json::parse_bounded(&text, 4).map_err(|e| format!("lab manifest: {e}"))?;
        let purpose = manifest.get("purpose").and_then(Json::as_str);
        if manifest.get("format").and_then(Json::as_str) != Some("routeloom-lab-site-v1")
            || !matches!(purpose, Some("development" | "production" | "import"))
        {
            return Err("invalid site purpose manifest".into());
        }
        manifest_site_id = Some(
            manifest
                .get("site_id")
                .and_then(Json::as_str)
                .and_then(parse_h16)
                .ok_or("site purpose manifest: invalid site_id")?,
        );
        if purpose != Some("development") {
            setup.purpose = if purpose == Some("production") {
                SitePurpose::Production
            } else {
                SitePurpose::Import
            };
            // A non-development manifest never loads inventory or enables
            // automatic approval, regardless of its displayed name.
        } else {
            let fingerprint = |name| -> Result<[u8; 32], String> {
                manifest
                    .get(name)
                    .and_then(Json::as_str)
                    .and_then(|s| parse_hex(s, 32))
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| format!("lab manifest: invalid {name}"))
            };
            let journal_path = dir.join("lab-init.journal");
            let journal_meta = std::fs::symlink_metadata(&journal_path)
                .map_err(|e| format!("lab initialization journal missing: {e}"))?;
            if !journal_meta.file_type().is_file() {
                return Err("lab initialization journal is not a regular file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if journal_meta.permissions().mode() & 0o077 != 0 {
                    return Err("lab initialization journal must be private (0600)".into());
                }
            }
            let journal = std::fs::read_to_string(&journal_path)
                .map_err(|e| format!("lab initialization journal: {e}"))?;
            let lines: Vec<_> = journal.lines().collect();
            let spec_recorded = lines
                .get(1)
                .and_then(|line| line.strip_prefix("spec:"))
                .is_some_and(|value| parse_hex(value, 32).is_some());
            let usb_recorded = lines
                .get(5)
                .and_then(|line| line.strip_prefix("usb-secret:"))
                .is_some_and(|value| parse_hex(value, 32).is_some());
            if !journal.ends_with("complete\n")
                || lines.len() != 7
                || lines[0] != "routeloom-lab-init-v1"
                || !spec_recorded
                || lines[2]
                    != format!(
                        "device-ca:{}",
                        hex_encode(&fingerprint("device_ca_fingerprint")?)
                    )
                || lines[3]
                    != format!(
                        "site-ca:{}",
                        hex_encode(&fingerprint("site_ca_fingerprint")?)
                    )
                || lines[4] != format!("sak:{}", hex_encode(&fingerprint("sak_fingerprint")?))
                || !usb_recorded
                || lines[6] != "complete"
            {
                return Err(
                    "lab manifest lacks a completed matching initialization journal".into(),
                );
            }
            let site_id = manifest
                .get("site_id")
                .and_then(Json::as_str)
                .and_then(parse_h16)
                .ok_or("lab manifest: invalid site_id")?;
            let path = dir.join("inventory.db");
            let inventory_meta = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("lab inventory database missing: {e}"))?;
            if !inventory_meta.file_type().is_file() {
                return Err("lab inventory database is not a regular file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if inventory_meta.permissions().mode() & 0o077 != 0 {
                    return Err("lab inventory database must be private (0600)".into());
                }
            }
            let db = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| format!("lab inventory: {e}"))?;
            // Rows and revision must come from one snapshot; an import
            // racing startup cannot yield a mixed policy generation.
            db.execute_batch("BEGIN DEFERRED TRANSACTION")
                .map_err(|e| format!("lab inventory: {e}"))?;
            let mut stmt = db.prepare("SELECT node, kid, role FROM inventory WHERE site_id=?1 AND completed=1 ORDER BY node LIMIT 129")
            .map_err(|e| format!("lab inventory: {e}"))?;
            let rows = stmt
                .query_map([format!("{site_id:016x}")], |row| {
                    let node: String = row.get(0)?;
                    let kid: String = row.get(1)?;
                    let role: u8 = row.get(2)?;
                    Ok((node, kid, role))
                })
                .map_err(|e| format!("lab inventory: {e}"))?;
            let mut inventory = Vec::new();
            for row in rows {
                let (node, kid, role) = row.map_err(|e| format!("lab inventory: {e}"))?;
                inventory.push(LabDevice {
                    node: parse_h16(&node).ok_or("lab inventory: invalid node")?,
                    kid: parse_hex(&kid, 32)
                        .and_then(|v| v.try_into().ok())
                        .ok_or("lab inventory: invalid kid")?,
                    role,
                });
            }
            let inventory_revision = db
                .query_row(
                    "SELECT revision FROM inventory_meta WHERE site_id=?1",
                    [format!("{site_id:016x}")],
                    |r| r.get(0),
                )
                .map_err(|e| format!("lab inventory: {e}"))?;
            db.execute_batch("COMMIT")
                .map_err(|e| format!("lab inventory: {e}"))?;
            setup.purpose = SitePurpose::Development;
            setup.lab = Some(LabBinding {
                site_id,
                site_ca_fingerprint: fingerprint("site_ca_fingerprint")?,
                device_ca_fingerprint: fingerprint("device_ca_fingerprint")?,
                sak_fingerprint: fingerprint("sak_fingerprint")?,
                inventory_revision,
                inventory,
            });
        }
    }
    let sak = FileRootSigner::load(&dir.join(SAK_FILE))
        .map_err(|e| format!("{}: {e}", dir.join(SAK_FILE).display()))?;
    if manifest_site_id.is_some_and(|site| site != sak.root_id()) {
        return Err("site purpose manifest belongs to a different site".into());
    }
    eprintln!("{FILE_KEY_CUSTODY_WARNING}");
    let store = SqliteSiteStore::open(&dir.join(STORE_FILE)).map_err(|e| e.to_string())?;
    SiteAuthority::open(&setup, Box::new(sak), Box::new(store), now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive_log::hex_lower;
    use crate::site::testkit;

    pub fn config_json(setup: &SiteSetup) -> String {
        format!(
            "{{\"format\":\"{CONFIG_FORMAT}\",\"site_cert_hex\":\"{}\",\"site_ca_pubkey_hex\":\"{}\",\"device_ca\":{{\"id\":\"{:016x}\",\"pubkey_hex\":\"{}\"}},\"channel\":{},\"channel_epoch\":{},\"gateways\":[{}]}}",
            hex_lower(&setup.site_cert),
            hex_lower(&setup.site_ca_pubkey.unwrap()),
            setup.device_ca_id,
            hex_lower(&setup.device_ca_pubkey),
            setup.channel,
            setup.channel_epoch,
            setup
                .gateways
                .iter()
                .map(|g| format!("\"{g:016x}\""))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    #[test]
    fn development_manifest_binds_inventory_and_policy_to_the_database() {
        use routeloom_provision::credential::credential_kid;
        use routeloom_provision::sha256::sha256;
        use routeloom_provision::signer::{write_private_file, RootSigner};
        let dir = std::env::temp_dir().join(format!(
            "routeloom-lab-config-{}-{}",
            std::process::id(),
            crate::now_ms()
        ));
        std::fs::create_dir(&dir).unwrap();
        let setup = testkit::setup();
        std::fs::write(dir.join(CONFIG_FILE), config_json(&setup)).unwrap();
        testkit::sak().save(&dir.join(SAK_FILE)).unwrap();
        let manifest = format!("{{\"format\":\"routeloom-lab-site-v1\",\"purpose\":\"development\",\"site_id\":\"{:016x}\",\"site_ca_fingerprint\":\"{}\",\"device_ca_fingerprint\":\"{}\",\"sak_fingerprint\":\"{}\"}}",
            testkit::SITE, hex_lower(&sha256(&testkit::site_ca_pub())), hex_lower(&sha256(&setup.device_ca_pubkey)), hex_lower(&credential_kid(&testkit::sak().pubkey())));
        write_private_file(&dir.join("lab-manifest.json"), manifest.as_bytes()).unwrap();
        let path = dir.join("inventory.db");
        write_private_file(&path, b"").unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE inventory_meta(site_id TEXT PRIMARY KEY, revision INTEGER NOT NULL); CREATE TABLE inventory(site_id TEXT NOT NULL, node TEXT NOT NULL, kid TEXT NOT NULL, role INTEGER NOT NULL, completed INTEGER NOT NULL);").unwrap();
        db.execute(
            "INSERT INTO inventory_meta VALUES (?1, 1)",
            [format!("{:016x}", testkit::SITE)],
        )
        .unwrap();
        let device = testkit::SimDevice::new(0x00a1_0000_0000_d0a1, 0xd1);
        db.execute(
            "INSERT INTO inventory VALUES (?1, ?2, ?3, 1, 1)",
            rusqlite::params![
                format!("{:016x}", testkit::SITE),
                format!("{:016x}", device.node),
                hex_lower(&device.kid)
            ],
        )
        .unwrap();
        assert!(open_dir(&dir, 1).is_err());
        let journal = format!(
            "routeloom-lab-init-v1\nspec:{}\ndevice-ca:{}\nsite-ca:{}\nsak:{}\nusb-secret:{}\ncomplete\n",
            hex_lower(&[0; 32]),
            hex_lower(&sha256(&setup.device_ca_pubkey)),
            hex_lower(&sha256(&testkit::site_ca_pub())),
            hex_lower(&credential_kid(&testkit::sak().pubkey())),
            hex_lower(&[0; 32]),
        );
        write_private_file(&dir.join("lab-init.journal"), journal.as_bytes()).unwrap();
        let mut authority = open_dir(&dir, 1).unwrap();
        authority
            .update_policy(&super::super::PolicyPatch {
                decision_mode: Some(super::super::DecisionMode::LabInventory),
                ..Default::default()
            })
            .unwrap();
        drop(authority);
        assert!(open_dir(&dir, 2).is_ok());
        db.execute("UPDATE inventory_meta SET revision=0", [])
            .unwrap();
        assert!(open_dir(&dir, 3).is_err());
        db.execute("UPDATE inventory_meta SET revision=1", [])
            .unwrap();
        std::fs::remove_file(dir.join("lab-manifest.json")).unwrap();
        assert!(open_dir(&dir, 4).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_directory_opens_and_refuses_bad_configs() {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-site-dir-{}-{}",
            std::process::id(),
            crate::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let setup = testkit::setup();
        std::fs::write(dir.join(CONFIG_FILE), config_json(&setup)).unwrap();
        testkit::sak().save(&dir.join(SAK_FILE)).unwrap();
        let authority = open_dir(&dir, 1).unwrap();
        assert_eq!(authority.site_id(), testkit::SITE);
        assert_eq!(authority.acl_network(), u64::from(testkit::NETWORK_LOW));
        drop(authority);
        let parsed = parse_setup(&config_json(&setup)).unwrap();
        assert_eq!(parsed.gateways, setup.gateways);
        for bad in [
            config_json(&setup).replace(CONFIG_FORMAT, "other"),
            config_json(&setup).replace("\"channel\"", "\"chan\""),
            config_json(&setup).replace("\"gateways\":[", "\"gateways\":[\"zz\","),
            "{}".to_string(),
        ] {
            assert!(parse_setup(&bad).is_err(), "{bad}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
