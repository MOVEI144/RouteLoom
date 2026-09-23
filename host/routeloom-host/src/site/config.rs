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
//! Issuing the SiteCert (`site-cert`, plan P7-2) is not implemented; a
//! development directory is assembled with the office tooling's key files
//! and `routeloom_provision::sdkv1::cert::cert_issue`.

use std::path::Path;

use routeloom_json::Json;
use routeloom_provision::signer::{FileRootSigner, FILE_KEY_CUSTODY_WARNING};

use super::records::{parse_h16, parse_hex};
use super::store::SqliteSiteStore;
use super::{SiteAuthority, SiteSetup};

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
    })
}

/// Opens the authority of `dir` (see the module docs).
pub fn open_dir(dir: &Path, now_ms: u64) -> Result<SiteAuthority, String> {
    let config = std::fs::read_to_string(dir.join(CONFIG_FILE))
        .map_err(|e| format!("cannot read {}: {e}", dir.join(CONFIG_FILE).display()))?;
    let setup = parse_setup(&config)?;
    let sak = FileRootSigner::load(&dir.join(SAK_FILE))
        .map_err(|e| format!("{}: {e}", dir.join(SAK_FILE).display()))?;
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
