//! `routeloomctl provision-devca-keygen | provision-pop-challenge |
//! provision-devcert | provision-identity | provision-siteca-keygen |
//! site-cert` — the SDK v1 office tooling of docs/design/sdk-v1/07 §6 (08
//! P7-1, P7-2). Local operations like the other `provision-*` verbs: they
//! never open the daemon socket and write only site-independent material
//! (NodeId, device key, DevCert, Site CA anchors) — never a network id,
//! site key or channel. `site-cert` (HQ, when the site PC is set up) is the
//! one site-bound exception: it binds a site_id to the site's SAK.
//!
//! Two key paths:
//! - device-generated (default, 07 §6 steps 2-3): `provision-pop-challenge`
//!   → the device maintenance verb answers with a proof of possession →
//!   `provision-devcert` verifies it, issues the DevCert and emits the
//!   identity bundle the device seals into `rlsec`/`rlident` itself;
//! - injected (below tier T1): `provision-identity` generates the key on
//!   this host, issues the DevCert and writes the full RLI1 plus the
//!   `rlsec` NVS set (`nvs_partition_gen.py` CSV + blobs). Every file that
//!   carries the device secret is created 0600 and never overwritten.
//!
//! The identity spec (`routeloom-identity-spec-v1`) is the per-product
//! template: `model`, `hw_rev`, `flags` and the RLI1 `anchors`. The per-device
//! `--node` and `--serial` come from the command line.

use std::path::{Path, PathBuf};

use routeloom_json::Json;

use crate::{is_hex, opt_value};

use routeloom_provision::credential::KeyLocation;
use routeloom_provision::sdkv1::devca::{
    devcert_issue, DevCertProfile, DeviceCaSigner, FileDeviceCaSigner, DEVICE_CA_CUSTODY_WARNING,
};
use routeloom_provision::sdkv1::identity::{
    identity_record_encode, AnchorKind, AnchorStatus, IdentityAnchor, IDENTITY_SEAL_COMMITTED,
};
use routeloom_provision::sdkv1::office::{
    identity_build_injected, identity_bundle_json, inventory_file_json, inventory_json,
    IdentityPlan,
};
use routeloom_provision::sdkv1::pop::{
    pop_challenge, pop_sign, pop_verify, POP_CHALLENGE_SIZE, POP_OBJECT_SIZE,
};
use routeloom_provision::sdkv1::rlsec::{rlsec_identity_readback, rlsec_identity_set};
use routeloom_provision::sdkv1::siteca::{
    sitecert_issue, FileSiteCaSigner, SiteCaSigner, SiteCertProfile, SITE_CA_CUSTODY_WARNING,
};
use routeloom_provision::signer::{
    generate_keypair, hex_decode_exact, hex_encode, write_private_file,
};

type DynError = Box<dyn std::error::Error>;

/// Printed by `provision-identity`: the injected-key path is weaker than
/// on-device generation and leaves the secret in the output files.
pub const INJECTED_KEY_WARNING: &str = "warning: injected device key (below tier T1) — the device secret was generated on this host and is in identity.rli1, rlident_i0.bin, rlident_i1.bin and rlsec-set.json (all 0600); flash them and destroy the directory. Prefer on-device generation (provision-pop-challenge + provision-devcert)";

/// The identity spec document marker.
pub const IDENTITY_SPEC_FORMAT: &str = "routeloom-identity-spec-v1";

/// `provision-devca-keygen --device-ca-id <16hex> --out <devca.key>`.
pub fn provision_devca_keygen_command(args: &[String]) -> Result<(), DynError> {
    let mut id: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--device-ca-id" => id = Some(opt_value(&mut args, "--device-ca-id")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            other => return Err(format!("unknown provision-devca-keygen option: {other}").into()),
        }
    }
    let id = hex64(
        "--device-ca-id",
        &id.ok_or("provision-devca-keygen requires --device-ca-id <16hex>")?,
    )?;
    let out = PathBuf::from(out.ok_or("provision-devca-keygen requires --out <path>")?);
    let signer = FileDeviceCaSigner::generate(id)?;
    signer.save(&out)?;
    eprintln!("{DEVICE_CA_CUSTODY_WARNING}");
    println!(
        "{{\"device_ca_id\":\"{id:016x}\",\"pubkey_hex\":\"{}\",\"key_file\":\"{}\"}}",
        hex_encode(&signer.pubkey()),
        json_path(&out)
    );
    Ok(())
}

/// `provision-pop-challenge --node <16hex>` — a fresh 32-byte challenge for
/// the device's proof of possession. Use it once.
pub fn provision_pop_challenge_command(args: &[String]) -> Result<(), DynError> {
    let mut node: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--node" => node = Some(opt_value(&mut args, "--node")?),
            other => return Err(format!("unknown provision-pop-challenge option: {other}").into()),
        }
    }
    let node = node_id(&node.ok_or("provision-pop-challenge requires --node <16hex>")?)?;
    println!(
        "{{\"node_id\":\"{node:016x}\",\"challenge_hex\":\"{}\"}}",
        hex_encode(&pop_challenge()?)
    );
    Ok(())
}

/// `provision-devcert --ca-key <devca.key> --spec <identity-spec.json>
/// --node <16hex> --serial <u32> --challenge <64hex> --pop <file>
/// --out-dir <dir>` — verify the device's proof of possession for exactly
/// this node and challenge, issue the DevCert, and write `devcert.cwt`,
/// `identity-bundle.json` (no secret) and `inventory.json`. Prints the
/// inventory line.
pub fn provision_devcert_command(args: &[String]) -> Result<(), DynError> {
    let mut opts = OfficeOptions::parse("provision-devcert", args, &["--challenge", "--pop"])?;
    let challenge_hex = opts.take("--challenge")?;
    let challenge: [u8; POP_CHALLENGE_SIZE] = hex_decode_exact(&challenge_hex, POP_CHALLENGE_SIZE)
        .ok_or("--challenge must be 64 hex")?
        .try_into()
        .expect("32 bytes");
    let pop_path = PathBuf::from(opts.take("--pop")?);
    let pop = read_object(&pop_path, POP_OBJECT_SIZE)?;
    let key = pop_verify(&pop, opts.node, &challenge)
        .map_err(|e| format!("proof of possession refused: {e}"))?;
    eprintln!("{DEVICE_CA_CUSTODY_WARNING}");
    let signer = FileDeviceCaSigner::load(&opts.ca_key)?;
    let devcert = devcert_issue(&signer, &key, &opts.profile)?;
    let bundle = identity_bundle_json(&opts.plan, &devcert)?;
    std::fs::create_dir_all(&opts.out_dir)?;
    write_new(&opts.out_dir.join("devcert.cwt"), &devcert)?;
    write_new(
        &opts.out_dir.join("identity-bundle.json"),
        bundle.as_bytes(),
    )?;
    write_new(
        &opts.out_dir.join("inventory.json"),
        inventory_file_json(&devcert)?.as_bytes(),
    )?;
    println!("{}", inventory_json(&devcert)?);
    Ok(())
}

/// `provision-identity --ca-key <devca.key> --spec <identity-spec.json>
/// --node <16hex> --serial <u32> --out-dir <dir>` — injected-key path: key
/// generated here, proof of possession made and checked like a device's,
/// DevCert issued, RLI1 built and read back, and the `rlsec` NVS set
/// written (`rlsec-nvs.csv` for `nvs_partition_gen.py`, the blob files and
/// the `rlsec-set.json` descriptor), plus `inventory.json`. Prints the
/// inventory line.
pub fn provision_identity_command(args: &[String]) -> Result<(), DynError> {
    let opts = OfficeOptions::parse("provision-identity", args, &[])?;
    eprintln!("{DEVICE_CA_CUSTODY_WARNING}");
    let signer = FileDeviceCaSigner::load(&opts.ca_key)?;
    let (secret, _) = generate_keypair()?;
    let challenge = pop_challenge()?;
    let pop = pop_sign(&secret, opts.node, KeyLocation::NvsPlaintext, &challenge)?;
    let key = pop_verify(&pop, opts.node, &challenge)?;
    let devcert = devcert_issue(&signer, &key, &opts.profile)?;
    let record = identity_build_injected(&opts.plan, &secret, &devcert)?;
    let set = rlsec_identity_set(&record)?;
    if rlsec_identity_readback(&set)? != record {
        return Err("rlsec set does not read back as the built identity".into());
    }
    // The directory holds the device secret: owner-only.
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&opts.out_dir)?;
    }
    write_new(&opts.out_dir.join("devcert.cwt"), &devcert)?;
    write_new(
        &opts.out_dir.join("inventory.json"),
        inventory_file_json(&devcert)?.as_bytes(),
    )?;
    write_private_file(
        &opts.out_dir.join("identity.rli1"),
        &identity_record_encode(&record, IDENTITY_SEAL_COMMITTED)?,
    )?;
    for entry in &set.entries {
        write_private_file(&opts.out_dir.join(entry.file_name()), &entry.bytes())?;
    }
    write_new(
        &opts.out_dir.join("rlsec-nvs.csv"),
        set.partition_csv().as_bytes(),
    )?;
    write_private_file(
        &opts.out_dir.join("rlsec-set.json"),
        set.descriptor_json().as_bytes(),
    )?;
    eprintln!("{INJECTED_KEY_WARNING}");
    println!("{}", inventory_json(&devcert)?);
    Ok(())
}

/// `provision-siteca-keygen --site-ca-id <16hex> --out <siteca.key>`.
pub fn provision_siteca_keygen_command(args: &[String]) -> Result<(), DynError> {
    let mut id: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--site-ca-id" => id = Some(opt_value(&mut args, "--site-ca-id")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            other => return Err(format!("unknown provision-siteca-keygen option: {other}").into()),
        }
    }
    let id = hex64(
        "--site-ca-id",
        &id.ok_or("provision-siteca-keygen requires --site-ca-id <16hex>")?,
    )?;
    if id == 0 || id == u64::MAX {
        return Err("--site-ca-id must not be 0 or all-ones".into());
    }
    let out = PathBuf::from(out.ok_or("provision-siteca-keygen requires --out <path>")?);
    let signer = FileSiteCaSigner::generate(id)?;
    signer.save(&out)?;
    eprintln!("{SITE_CA_CUSTODY_WARNING}");
    println!(
        "{{\"site_ca_id\":\"{id:016x}\",\"pubkey_hex\":\"{}\",\"key_file\":\"{}\"}}",
        hex_encode(&signer.pubkey()),
        json_path(&out)
    );
    Ok(())
}

/// `site-cert --ca-key <siteca.key> --site-id <16hex> --sak-pubkey <128hex>
/// --network-low32 <8hex> --site-epoch <u32> --serial <u32> --out
/// <sitecert.cwt>` — HQ issues the SiteCert binding the site to its SAK
/// (07 §6, P7-2). The SAK public half comes from the site PC out of band;
/// the Site Authority refuses to start on a mismatch, so a wrong key here
/// is useless rather than dangerous. Never overwrites the output.
pub fn site_cert_command(args: &[String]) -> Result<(), DynError> {
    let mut ca_key: Option<String> = None;
    let mut site_id: Option<String> = None;
    let mut sak_pubkey: Option<String> = None;
    let mut network_low32: Option<String> = None;
    let mut site_epoch: Option<String> = None;
    let mut serial: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ca-key" => ca_key = Some(opt_value(&mut args, "--ca-key")?),
            "--site-id" => site_id = Some(opt_value(&mut args, "--site-id")?),
            "--sak-pubkey" => sak_pubkey = Some(opt_value(&mut args, "--sak-pubkey")?),
            "--network-low32" => network_low32 = Some(opt_value(&mut args, "--network-low32")?),
            "--site-epoch" => site_epoch = Some(opt_value(&mut args, "--site-epoch")?),
            "--serial" => serial = Some(opt_value(&mut args, "--serial")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            other => return Err(format!("unknown site-cert option: {other}").into()),
        }
    }
    let site_id = hex64(
        "--site-id",
        &site_id.ok_or("site-cert requires --site-id <16hex>")?,
    )?;
    if site_id == 0 || site_id == u64::MAX {
        return Err("--site-id must not be 0 or all-ones".into());
    }
    let sak_pubkey: [u8; 64] = hex_decode_exact(
        &sak_pubkey.ok_or("site-cert requires --sak-pubkey <128hex>")?,
        64,
    )
    .ok_or("--sak-pubkey must be 128 hex")?
    .try_into()
    .expect("64 bytes");
    let low32_text = network_low32.ok_or("site-cert requires --network-low32 <8hex>")?;
    if !is_hex(&low32_text, 8) {
        return Err("--network-low32 must be 8 hex".into());
    }
    let network_low32 = u32::from_str_radix(&low32_text, 16).expect("8 hex");
    if network_low32 == 0 {
        return Err("--network-low32 must be nonzero".into());
    }
    let site_epoch: u32 = site_epoch
        .ok_or("site-cert requires --site-epoch <u32>")?
        .parse()
        .map_err(|_| "--site-epoch must be a u32")?;
    let serial: u32 = serial
        .ok_or("site-cert requires --serial <u32>")?
        .parse()
        .map_err(|_| "--serial must be a u32")?;
    let out = PathBuf::from(out.ok_or("site-cert requires --out <path>")?);
    eprintln!("{SITE_CA_CUSTODY_WARNING}");
    let signer = FileSiteCaSigner::load(
        &ca_key
            .map(PathBuf::from)
            .ok_or("site-cert requires --ca-key <file>")?,
    )?;
    let cert = sitecert_issue(
        &signer,
        site_id,
        &sak_pubkey,
        &SiteCertProfile {
            network_low32,
            site_epoch,
            serial,
        },
    )
    .map_err(|e| format!("site-cert refused: {e}"))?;
    write_new(&out, &cert)?;
    let network = (u64::from(site_epoch) << 32) | u64::from(network_low32);
    println!(
        "{{\"site_id\":\"{site_id:016x}\",\"network\":\"{network:016x}\",\"site_epoch\":{site_epoch},\"serial\":{serial},\"cert_file\":\"{}\"}}",
        json_path(&out)
    );
    Ok(())
}

// --- shared option parsing ------------------------------------------------------

struct OfficeOptions {
    ca_key: PathBuf,
    out_dir: PathBuf,
    node: u64,
    profile: DevCertProfile,
    plan: IdentityPlan,
    extra: Vec<(String, String)>,
}

impl OfficeOptions {
    fn parse(verb: &str, args: &[String], extra_flags: &[&str]) -> Result<Self, DynError> {
        let mut ca_key: Option<String> = None;
        let mut spec: Option<String> = None;
        let mut node: Option<String> = None;
        let mut serial: Option<String> = None;
        let mut out_dir: Option<String> = None;
        let mut extra = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--ca-key" => ca_key = Some(opt_value(&mut args, "--ca-key")?),
                "--spec" => spec = Some(opt_value(&mut args, "--spec")?),
                "--node" => node = Some(opt_value(&mut args, "--node")?),
                "--serial" => serial = Some(opt_value(&mut args, "--serial")?),
                "--out-dir" => out_dir = Some(opt_value(&mut args, "--out-dir")?),
                flag if extra_flags.contains(&flag) => {
                    extra.push((flag.to_string(), opt_value(&mut args, flag)?))
                }
                other => return Err(format!("unknown {verb} option: {other}").into()),
            }
        }
        let node = node_id(&node.ok_or_else(|| format!("{verb} requires --node <16hex>"))?)?;
        let serial: u32 = serial
            .ok_or_else(|| format!("{verb} requires --serial <u32>"))?
            .parse()
            .map_err(|_| "--serial must be a u32")?;
        let spec = PathBuf::from(spec.ok_or_else(|| format!("{verb} requires --spec <file>"))?);
        let (profile, plan) = identity_spec(&read_json(&spec)?, node, serial)?;
        Ok(Self {
            ca_key: PathBuf::from(
                ca_key.ok_or_else(|| format!("{verb} requires --ca-key <file>"))?,
            ),
            out_dir: PathBuf::from(
                out_dir.ok_or_else(|| format!("{verb} requires --out-dir <dir>"))?,
            ),
            node,
            profile,
            plan,
            extra,
        })
    }

    fn take(&mut self, flag: &str) -> Result<String, DynError> {
        let index = self
            .extra
            .iter()
            .position(|(name, _)| name == flag)
            .ok_or_else(|| format!("{flag} is required"))?;
        Ok(self.extra.remove(index).1)
    }
}

fn read_json(path: &Path) -> Result<Json, DynError> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(routeloom_json::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?)
}

fn json_path(path: &Path) -> String {
    routeloom_json::escape_string(&path.to_string_lossy())
}

fn hex64(flag: &str, value: &str) -> Result<u64, DynError> {
    if !is_hex(value, 16) {
        return Err(format!("{flag} must be a 16-hex id").into());
    }
    Ok(u64::from_str_radix(value, 16).expect("16 hex"))
}

fn node_id(value: &str) -> Result<u64, DynError> {
    let node = hex64("--node", value)?;
    if node == 0 || node == u64::MAX {
        return Err("--node must not be 0 or all-ones".into());
    }
    Ok(node)
}

/// A proof-of-possession object as the device verb hands it over: raw
/// bytes, or the same bytes as one hex line.
fn read_object(path: &Path, max: usize) -> Result<Vec<u8>, DynError> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        let text = text.trim();
        if !text.is_empty() && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(hex_decode_exact(text, text.len() / 2).expect("hex checked"));
        }
    }
    if bytes.len() > max {
        return Err(format!("{}: larger than {max} bytes", path.display()).into());
    }
    Ok(bytes)
}

/// Create a new file (never overwrite a previous device's output).
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), DynError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e} (refusing to overwrite)", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

/// `routeloom-identity-spec-v1` → (DevCert profile, RLI1 plan).
fn identity_spec(
    doc: &Json,
    node: u64,
    serial: u32,
) -> Result<(DevCertProfile, IdentityPlan), DynError> {
    if doc.get("format").and_then(|v| v.as_str()) != Some(IDENTITY_SPEC_FORMAT) {
        return Err(format!("spec format must be {IDENTITY_SPEC_FORMAT}").into());
    }
    let number = |key: &str, max: u64| -> Result<u64, DynError> {
        doc.get(key)
            .and_then(|v| v.as_u64())
            .filter(|v| *v <= max)
            .ok_or_else(|| format!("spec field \"{key}\" must be an integer <= {max}").into())
    };
    let profile = DevCertProfile {
        model: number("model", u64::from(u16::MAX))? as u16,
        hw_rev: number("hw_rev", u64::from(u8::MAX))? as u8,
        serial,
    };
    let flags = match doc.get("flags") {
        None => 0,
        Some(_) => number("flags", u64::from(u8::MAX))? as u8,
    };
    let mut anchors = Vec::new();
    for entry in doc.get("anchors").and_then(|v| v.as_array()).unwrap_or(&[]) {
        let id_text = entry
            .get("anchor_id")
            .and_then(|v| v.as_str())
            .ok_or("anchor_id must be a 16-hex string")?;
        let kind = match entry.get("kind").and_then(|v| v.as_str()) {
            Some("site-ca") => AnchorKind::SiteCa,
            Some("assignment-verifier") => AnchorKind::AssignmentVerifier,
            _ => return Err("anchor kind must be site-ca|assignment-verifier".into()),
        };
        let status = match entry
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("active")
        {
            "active" => AnchorStatus::Active,
            "disabled" => AnchorStatus::Disabled,
            _ => return Err("anchor status must be active|disabled".into()),
        };
        let pubkey: [u8; 64] = entry
            .get("pubkey_hex")
            .and_then(|v| v.as_str())
            .and_then(|s| hex_decode_exact(s, 64))
            .ok_or("anchor pubkey_hex must be 64 bytes hex")?
            .try_into()
            .expect("64 bytes");
        anchors.push(IdentityAnchor {
            anchor_id: hex64("anchor_id", id_text)?,
            kind,
            status,
            pubkey,
        });
    }
    Ok((
        profile,
        IdentityPlan {
            node_id: node,
            flags,
            anchors,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_provision::sdkv1::pop::pop_sign;
    use routeloom_provision::signer::test_keypair;

    fn spec_text() -> String {
        format!(
            r#"{{
  "format": "routeloom-identity-spec-v1",
  "model": 17,
  "hw_rev": 2,
  "flags": 0,
  "anchors": [
    {{"anchor_id": "05ca000000000001", "kind": "site-ca", "status": "active", "pubkey_hex": "{}"}}
  ]
}}"#,
            hex_encode(&test_keypair(0x52).1)
        )
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rl-ctl-office-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn spec_parsing() {
        let doc = routeloom_json::parse(&spec_text()).unwrap();
        let (profile, plan) = identity_spec(&doc, 0x1234, 9).unwrap();
        assert_eq!(
            profile,
            DevCertProfile {
                model: 17,
                hw_rev: 2,
                serial: 9
            }
        );
        assert_eq!(plan.node_id, 0x1234);
        assert_eq!(plan.anchors.len(), 1);
        assert_eq!(plan.anchors[0].anchor_id, 0x05CA_0000_0000_0001);
        let bad = spec_text().replace("\"site-ca\"", "\"root\"");
        assert!(identity_spec(&routeloom_json::parse(&bad).unwrap(), 1, 1).is_err());
        let bad = spec_text().replace("\"hw_rev\": 2", "\"hw_rev\": 300");
        assert!(identity_spec(&routeloom_json::parse(&bad).unwrap(), 1, 1).is_err());
        let bad = spec_text().replace("routeloom-identity-spec-v1", "other");
        assert!(identity_spec(&routeloom_json::parse(&bad).unwrap(), 1, 1).is_err());
    }

    #[test]
    fn injected_and_device_generated_flows() {
        let dir = scratch("flows");
        let key = dir.join("devca.key");
        FileDeviceCaSigner::from_secret(0x0DCA_0000_0000_0001, &[0x51; 32])
            .unwrap()
            .save(&key)
            .unwrap();
        let spec = dir.join("spec.json");
        std::fs::write(&spec, spec_text()).unwrap();

        // Injected key: full rlsec set, secret-bearing files 0600.
        let out = dir.join("injected");
        provision_identity_command(&args(&[
            "--ca-key",
            key.to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
            "--node",
            "00a1000000001234",
            "--serial",
            "90211",
            "--out-dir",
            out.to_str().unwrap(),
        ]))
        .unwrap();
        for name in [
            "devcert.cwt",
            "identity.rli1",
            "inventory.json",
            "rlident_i0.bin",
            "rlident_i1.bin",
            "rlsec-nvs.csv",
            "rlsec-set.json",
        ] {
            assert!(out.join(name).exists(), "{name}");
        }
        let i0 = std::fs::read(out.join("rlident_i0.bin")).unwrap();
        assert_eq!(i0, std::fs::read(out.join("rlident_i1.bin")).unwrap());
        assert_eq!(i0, std::fs::read(out.join("identity.rli1")).unwrap());
        let record = routeloom_provision::sdkv1::identity::identity_record_decode(&i0).unwrap();
        assert_eq!(record.node_id, 0x00A1_0000_0000_1234);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in [
                "identity.rli1",
                "rlident_i0.bin",
                "rlident_i1.bin",
                "rlsec-set.json",
            ] {
                let mode = std::fs::metadata(out.join(name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o077, 0, "{name} must be private");
            }
        }
        // Re-running into the same directory never overwrites.
        assert!(provision_identity_command(&args(&[
            "--ca-key",
            key.to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
            "--node",
            "00a1000000001234",
            "--serial",
            "90211",
            "--out-dir",
            out.to_str().unwrap(),
        ]))
        .is_err());

        // Device-generated key: PoP (hex file) → DevCert + bundle.
        let challenge = [0x5A_u8; 32];
        let (device_secret, _) = test_keypair(0x54);
        let pop = pop_sign(
            &device_secret,
            0x00A1_0000_0000_1234,
            KeyLocation::NvsPlaintext,
            &challenge,
        )
        .unwrap();
        let pop_path = dir.join("pop.hex");
        std::fs::write(&pop_path, format!("{}\n", hex_encode(&pop))).unwrap();
        let out = dir.join("devgen");
        let base = [
            "--ca-key",
            key.to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
            "--serial",
            "90211",
            "--pop",
            pop_path.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
        ];
        // Wrong challenge or wrong node: no DevCert.
        let bad_challenge = "5b".repeat(32);
        let mut wrong = base.to_vec();
        wrong.extend(["--node", "00a1000000001234", "--challenge", &bad_challenge]);
        assert!(provision_devcert_command(&args(&wrong)).is_err());
        let mut wrong = base.to_vec();
        let good_challenge = "5a".repeat(32);
        wrong.extend(["--node", "00a1000000001235", "--challenge", &good_challenge]);
        assert!(provision_devcert_command(&args(&wrong)).is_err());
        assert!(!out.join("devcert.cwt").exists());
        let mut good = base.to_vec();
        good.extend(["--node", "00a1000000001234", "--challenge", &good_challenge]);
        provision_devcert_command(&args(&good)).unwrap();
        let bundle = std::fs::read_to_string(out.join("identity-bundle.json")).unwrap();
        assert!(bundle.contains("routeloom-identity-bundle-v1"));
        assert!(!bundle.contains(&hex_encode(&device_secret)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn siteca_keygen_and_site_cert_flow() {
        use routeloom_provision::sdkv1::siteca::{sitecert_verify, FileSiteCaSigner};
        use routeloom_provision::signer::test_keypair;

        let dir = scratch("sitecert");
        let key = dir.join("siteca.key");
        provision_siteca_keygen_command(&args(&[
            "--site-ca-id",
            "05ca000000000001",
            "--out",
            key.to_str().unwrap(),
        ]))
        .unwrap();
        let ca = FileSiteCaSigner::load(&key).unwrap();
        assert!(provision_siteca_keygen_command(&args(&[
            "--site-ca-id",
            "05ca000000000001",
            "--out",
            key.to_str().unwrap(),
        ]))
        .is_err());

        let (_, sak_pub) = test_keypair(0x53);
        let sak_hex = hex_encode(&sak_pub);
        let out = dir.join("sitecert.cwt");
        let good = args(&[
            "--ca-key",
            key.to_str().unwrap(),
            "--site-id",
            "5173000000000042",
            "--sak-pubkey",
            &sak_hex,
            "--network-low32",
            "0a1b2c3d",
            "--site-epoch",
            "3",
            "--serial",
            "7",
            "--out",
            out.to_str().unwrap(),
        ]);
        site_cert_command(&good).unwrap();
        let cert = std::fs::read(&out).unwrap();
        let claims = sitecert_verify(&cert, 0x05CA_0000_0000_0001, &ca.pubkey()).unwrap();
        assert_eq!(claims.subject, 0x5173_0000_0000_0042);
        assert_eq!(claims.network_low32, 0x0A1B_2C3D);
        // Never overwrite; bad inputs mint nothing.
        assert!(site_cert_command(&good).is_err());
        let zero_pubkey = "00".repeat(64);
        for (flag, value) in [
            ("--sak-pubkey", zero_pubkey.as_str()),
            ("--sak-pubkey", "zz"),
            ("--network-low32", "00000000"),
            ("--network-low32", "0a1b2c3"),
            ("--site-id", "0000000000000000"),
            ("--site-epoch", "4294967296"),
            ("--serial", "nope"),
        ] {
            let mut argv = good.clone();
            let at = argv.iter().position(|part| part == flag).unwrap() + 1;
            argv[at] = value.to_string();
            let _ = std::fs::remove_file(&out);
            assert!(site_cert_command(&argv).is_err(), "{flag}={value}");
            assert!(!out.exists());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inventory_file_lands_next_to_the_bundle() {
        let dir = scratch("inventory");
        let key = dir.join("devca.key");
        FileDeviceCaSigner::from_secret(0x0DCA_0000_0000_0001, &[0x51; 32])
            .unwrap()
            .save(&key)
            .unwrap();
        let spec = dir.join("spec.json");
        std::fs::write(&spec, spec_text()).unwrap();
        let out = dir.join("devgen");
        let challenge = "5a".repeat(32);
        let (device_secret, _) = test_keypair(0x54);
        let pop = pop_sign(
            &device_secret,
            0x00A1_0000_0000_1234,
            KeyLocation::NvsPlaintext,
            &[0x5A; 32],
        )
        .unwrap();
        let pop_path = dir.join("pop.bin");
        std::fs::write(&pop_path, pop).unwrap();
        provision_devcert_command(&args(&[
            "--ca-key",
            key.to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
            "--node",
            "00a1000000001234",
            "--serial",
            "90211",
            "--challenge",
            &challenge,
            "--pop",
            pop_path.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
        ]))
        .unwrap();
        let record =
            routeloom_json::parse(&std::fs::read_to_string(out.join("inventory.json")).unwrap())
                .unwrap();
        assert_eq!(
            record.get("format").and_then(|v| v.as_str()),
            Some("routeloom-inventory-v1")
        );
        assert_eq!(
            record.get("node_id").and_then(|v| v.as_str()),
            Some("00a1000000001234")
        );
        assert_eq!(
            record.get("cert_serial").and_then(|v| v.as_u64()),
            Some(90211)
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
