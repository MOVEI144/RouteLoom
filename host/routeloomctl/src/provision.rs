//! `routeloomctl provision-*` — the local provisioning operations of
//! 04-provisioning-lifecycle.md §4.4/§4.5. Unlike every other verb these
//! never touch the daemon socket: they build, sign and verify the
//! artifacts the P-A1 manufactured path and the RTM1 in-band lifecycle
//! consume — dev root keys, committed RLT1 trust images, manufactured
//! NVS blob sets and signed RTM1 manifests — through the
//! `routeloom-provision` crate, the host mirror of the device codecs.
//!
//! Image/credential inputs are JSON spec documents
//! (`routeloom-trust-image-spec-v1`, `routeloom-credential-spec-v1`) —
//! the same descriptor shape `protocol/provisioning-golden/` carries, so
//! a spec file is the audit record of exactly what was provisioned.

use std::path::{Path, PathBuf};

use routeloom_json::Json;

use crate::{is_hex, opt_value};

use routeloom_provision::credential::{
    credential_kid, credential_record_encode, CredStatus, DeviceCredential, KeyLocation,
    CREDENTIAL_GRANT_MAX, CRED_SEAL_COMMITTED,
};
use routeloom_provision::image::{
    image_decode, image_encode, image_validate, AnchorStatus, KeyStatus, TrustAnchor, TrustImage,
    TrustKeyRecord, TrustRevocation, TRUST_MAGIC, TRUST_SEAL_COMMITTED,
};
use routeloom_provision::manifest::manifest_sign;
use routeloom_provision::nvs::manufacture_nvs_set;
use routeloom_provision::signer::{
    hex_decode_exact, hex_encode, FileAuthoritySigner, FileRootSigner, RootSigner,
    FILE_KEY_CUSTODY_WARNING,
};
use routeloom_provision::verify::{verify_manifest, Verdict};

type DynError = Box<dyn std::error::Error>;

/// `provision-keygen --root-id <16hex> --out <key.json>` — generate a dev
/// P-256 root pair, write the `routeloom-root-key-v1` document (mode
/// 0600, never overwriting), print the custody warning on stderr and the
/// public identity on stdout.
/// `provision-authority-keygen --authority-id <16hex> --out <key.json>` —
/// generate a dev P-256 CONFIG AUTHORITY pair for the RLCP1_COSE_ESP256
/// permit/recovery profile, writing the
/// `routeloom-config-authority-key-v1` document (mode 0600, never
/// overwriting). The document is NOT a root key — neither loader
/// accepts the other's file — and the daemon's `--config-authority`
/// must equal `--authority-id` for the key to sign.
pub fn provision_authority_keygen_command(args: &[String]) -> Result<(), DynError> {
    let mut authority_id: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--authority-id" => authority_id = Some(opt_value(&mut args, "--authority-id")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            other => {
                return Err(format!("unknown provision-authority-keygen option: {other}").into())
            }
        }
    }
    let authority_id = want_hex64(
        "--authority-id",
        authority_id.ok_or("provision-authority-keygen requires --authority-id <16hex>")?,
    )?;
    if authority_id == 0 {
        return Err("--authority-id must be nonzero".into());
    }
    let out = PathBuf::from(out.ok_or("provision-authority-keygen requires --out <path>")?);
    let signer = FileAuthoritySigner::generate(authority_id)?;
    signer.save(&out)?;
    eprintln!("{FILE_KEY_CUSTODY_WARNING}");
    println!(
        "{{\"authority_id\":\"{authority_id:016x}\",\"pubkey_hex\":\"{}\",\"key_file\":\"{}\"}}",
        hex_encode(&signer.pubkey()),
        out.display()
    );
    Ok(())
}

pub fn provision_keygen_command(args: &[String]) -> Result<(), DynError> {
    let mut root_id: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root-id" => root_id = Some(opt_value(&mut args, "--root-id")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            other => return Err(format!("unknown provision-keygen option: {other}").into()),
        }
    }
    let root_id = want_hex64(
        "--root-id",
        root_id.ok_or("provision-keygen requires --root-id <16hex>")?,
    )?;
    if root_id == 0 {
        return Err("--root-id must be nonzero".into());
    }
    let out = PathBuf::from(out.ok_or("provision-keygen requires --out <path>")?);
    let signer = FileRootSigner::generate(root_id)?;
    signer.save(&out)?;
    eprintln!("{FILE_KEY_CUSTODY_WARNING}");
    println!(
        "{{\"root_id\":\"{root_id:016x}\",\"pubkey_hex\":\"{}\",\"key_file\":\"{}\"}}",
        hex_encode(&signer.pubkey()),
        out.display()
    );
    Ok(())
}

/// `provision-image --spec <image-spec.json> --out <image.rlt1>
/// [--nvs-dir <dir>] [--credential <cred-spec.json>]` — build the
/// committed RLT1 record for the spec's TrustImage; with `--nvs-dir`
/// also emit the P-A1 manufactured blob set (rltrust t0/t1, rlcred d0/d1
/// when `--credential` is given, rlboot session=0) plus the JSON
/// descriptor.
pub fn provision_image_command(args: &[String]) -> Result<(), DynError> {
    let mut spec: Option<String> = None;
    let mut out: Option<String> = None;
    let mut nvs_dir: Option<String> = None;
    let mut credential: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--spec" => spec = Some(opt_value(&mut args, "--spec")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            "--nvs-dir" => nvs_dir = Some(opt_value(&mut args, "--nvs-dir")?),
            "--credential" => credential = Some(opt_value(&mut args, "--credential")?),
            other => return Err(format!("unknown provision-image option: {other}").into()),
        }
    }
    let spec = PathBuf::from(spec.ok_or("provision-image requires --spec <image-spec.json>")?);
    let out = PathBuf::from(out.ok_or("provision-image requires --out <image.rlt1>")?);
    let image = trust_image_from_spec(&read_json(&spec)?)?;
    let record = image_encode(&image, TRUST_SEAL_COMMITTED)?;
    std::fs::write(&out, &record)?;

    if let Some(dir) = nvs_dir {
        let dir = PathBuf::from(dir);
        let credential = match credential {
            Some(path) => Some(credential_from_spec(&read_json(Path::new(&path))?)?),
            None => None,
        };
        let set = manufacture_nvs_set(&image, credential.as_ref(), 0)?;
        write_private_nvs_set(&dir, &set)?;
    }
    println!(
        "{{\"image\":\"{}\",\"image_bytes\":{},\"fingerprint\":\"{}\"}}",
        out.display(),
        record.len(),
        hex_encode(&routeloom_provision::image::image_fingerprint(&record)?)
    );
    Ok(())
}

#[cfg(unix)]
fn write_private_nvs_set(
    dir: &Path,
    set: &routeloom_provision::nvs::ManufacturedNvs,
) -> Result<(), DynError> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if !dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(dir)?;
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o777 != 0o700 {
        return Err("nvs-dir must be an owner-only directory (0700)".into());
    }
    // The descriptor also contains credential data_hex. Never truncate an
    // existing path (including symlinks), and set permissions at creation.
    let write = |name: &str, bytes: &[u8]| -> Result<(), DynError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(name))?;
        file.write_all(bytes)?;
        Ok(())
    };
    for entry in &set.entries {
        write(&entry.file_name(), &entry.bytes())?;
    }
    write("nvs-set.json", set.descriptor_json().as_bytes())
}

#[cfg(windows)]
fn write_private_nvs_set(
    dir: &Path,
    set: &routeloom_provision::nvs::ManufacturedNvs,
) -> Result<(), DynError> {
    use std::io::Write;
    routeloom_peercred::create_private_dir_all(dir)?;
    routeloom_peercred::verify_private_dir_perms(dir)?;
    let write = |name: &str, bytes: &[u8]| -> Result<(), DynError> {
        let mut file = routeloom_peercred::open_private_file_for_write(&dir.join(name))?;
        file.write_all(bytes)?;
        Ok(())
    };
    for entry in &set.entries {
        write(&entry.file_name(), &entry.bytes())?;
    }
    write("nvs-set.json", set.descriptor_json().as_bytes())
}

#[cfg(all(test, windows))]
mod windows_private_nvs_tests {
    use super::*;

    #[test]
    fn nvs_output_has_owner_only_dacl() {
        let dir =
            std::env::temp_dir().join(format!("routeloom-private-nvs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let set = routeloom_provision::nvs::ManufacturedNvs {
            entries: vec![routeloom_provision::nvs::NvsEntry {
                namespace: routeloom_provision::nvs::NVS_NAMESPACE_CRED,
                key: "d0",
                value: routeloom_provision::nvs::NvsValue::Blob(vec![7; 32]),
            }],
        };
        write_private_nvs_set(&dir, &set).unwrap();
        routeloom_peercred::verify_private_dir_perms(&dir).unwrap();
        routeloom_peercred::verify_private_file_perms(&dir.join("nvs-set.json")).unwrap();
        routeloom_peercred::verify_private_file_perms(&dir.join("rlcred_d0.bin")).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// `provision-manifest --image <spec-or-rlt1> --key <root.key> --out
/// <manifest>` — sign the image's RLT1 body into an RTM1 object under
/// the dev root key. The AAD binds the image's own network — the only
/// network a device can ever accept it on.
pub fn provision_manifest_command(args: &[String]) -> Result<(), DynError> {
    let mut image_path: Option<String> = None;
    let mut key: Option<String> = None;
    let mut out: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--image" => image_path = Some(opt_value(&mut args, "--image")?),
            "--key" => key = Some(opt_value(&mut args, "--key")?),
            "--out" => out = Some(opt_value(&mut args, "--out")?),
            other => return Err(format!("unknown provision-manifest option: {other}").into()),
        }
    }
    let image = load_image(&PathBuf::from(
        image_path.ok_or("provision-manifest requires --image <spec.json|image.rlt1>")?,
    ))?;
    let key = PathBuf::from(key.ok_or("provision-manifest requires --key <root.key>")?);
    let out = PathBuf::from(out.ok_or("provision-manifest requires --out <manifest>")?);
    eprintln!("{FILE_KEY_CUSTODY_WARNING}");
    let signer = FileRootSigner::load(&key)?;
    let object = manifest_sign(&image, &signer)?;
    std::fs::write(&out, &object)?;
    println!(
        "{{\"manifest\":\"{}\",\"manifest_bytes\":{},\"root_id\":\"{:016x}\",\"store_epoch\":{},\"network\":\"{:016x}\"}}",
        out.display(),
        object.len(),
        signer.root_id(),
        image.store_epoch,
        image.network,
    );
    Ok(())
}

/// `provision-verify --manifest <file> --current <spec-or-rlt1>` — the
/// offline §4.5.1 acceptance check: exactly the decision a device whose
/// committed store held `current` would make, without performing the
/// physical commit. Prints the verdict JSON; exits nonzero on refusal.
pub fn provision_verify_command(args: &[String]) -> Result<(), DynError> {
    let mut manifest: Option<String> = None;
    let mut current: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => manifest = Some(opt_value(&mut args, "--manifest")?),
            "--current" => current = Some(opt_value(&mut args, "--current")?),
            other => return Err(format!("unknown provision-verify option: {other}").into()),
        }
    }
    let manifest = PathBuf::from(manifest.ok_or("provision-verify requires --manifest <file>")?);
    let current = load_image(&PathBuf::from(
        current.ok_or("provision-verify requires --current <spec.json|image.rlt1>")?,
    ))?;
    let object = std::fs::read(&manifest)?;
    let report = verify_manifest(&current, &object);
    let fmt_opt_u64 = |v: Option<u64>| match v {
        Some(v) => format!("\"{v:016x}\""),
        None => "null".to_string(),
    };
    let fmt_opt_u32 = |v: Option<u32>| match v {
        Some(v) => format!("{v}"),
        None => "null".to_string(),
    };
    match &report.verdict {
        Verdict::Accept(image) => {
            println!(
                "{{\"verdict\":\"accept\",\"root_id\":{},\"claimed_epoch\":{},\"claimed_network\":{},\"new_epoch\":{},\"anchors\":{},\"keys\":{},\"revocations\":{}}}",
                fmt_opt_u64(report.root_id),
                fmt_opt_u32(report.claimed_epoch),
                fmt_opt_u64(report.claimed_network),
                image.store_epoch,
                image.anchors.len(),
                image.keys.len(),
                image.revocations.len(),
            );
            Ok(())
        }
        Verdict::Refuse(error) => {
            println!(
                "{{\"verdict\":\"refuse\",\"code\":\"{:?}\",\"detail\":\"{}\",\"root_id\":{},\"claimed_epoch\":{},\"claimed_network\":{}}}",
                error.code,
                error.detail,
                fmt_opt_u64(report.root_id),
                fmt_opt_u32(report.claimed_epoch),
                fmt_opt_u64(report.claimed_network),
            );
            Err(format!("manifest refused ({:?})", error.code).into())
        }
    }
}

// --- spec documents --------------------------------------------------------

fn read_json(path: &Path) -> Result<Json, DynError> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(routeloom_json::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?)
}

/// Load a TrustImage from either a committed RLT1 record (RLT1 magic)
/// or an image spec document — the two ways an operator holds one.
fn load_image(path: &Path) -> Result<TrustImage, DynError> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() >= 4 && bytes[..4] == TRUST_MAGIC.to_be_bytes() {
        return Ok(image_decode(&bytes)?);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{}: neither an RLT1 record nor a JSON spec", path.display()))?;
    let doc = routeloom_json::parse(text).map_err(|e| format!("{}: {e}", path.display()))?;
    let image = trust_image_from_spec(&doc)?;
    image_validate(&image)?;
    Ok(image)
}

/// A 16-hex string field (u64 ids are hex strings in every workspace
/// document — numbers would lose precision through f64 elsewhere).
fn spec_id(doc: &Json, key: &str) -> Result<u64, DynError> {
    let text = doc
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("spec field \"{key}\" must be a 16-hex string"))?;
    if !is_hex(text, 16) {
        return Err(format!("spec field \"{key}\" must be a 16-hex string").into());
    }
    Ok(u64::from_str_radix(text, 16).expect("16 hex"))
}

fn spec_u32(doc: &Json, key: &str) -> Result<u32, DynError> {
    doc.get(key)
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| format!("spec field \"{key}\" must be a u32").into())
}

fn spec_u8(doc: &Json, key: &str) -> Result<u8, DynError> {
    doc.get(key)
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(|| format!("spec field \"{key}\" must be a u8").into())
}

fn spec_hex<const N: usize>(doc: &Json, key: &str) -> Result<[u8; N], DynError> {
    let text = doc
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("spec field \"{key}\" must be a {N}-byte hex string"))?;
    let bytes = hex_decode_exact(text, N)
        .ok_or_else(|| format!("spec field \"{key}\" must be {N} bytes hex"))?;
    Ok(bytes.try_into().expect("N"))
}

fn spec_array<'a>(doc: &'a Json, key: &str) -> Result<&'a [Json], DynError> {
    Ok(doc.get(key).and_then(|v| v.as_array()).unwrap_or(&[]))
}

fn want_hex64(flag: &str, value: String) -> Result<u64, DynError> {
    if !is_hex(&value, 16) {
        return Err(format!("{flag} must be a 16-hex id").into());
    }
    Ok(u64::from_str_radix(&value, 16).expect("16 hex"))
}

fn anchor_status(text: Option<&str>) -> Result<AnchorStatus, DynError> {
    match text.unwrap_or("active") {
        "active" => Ok(AnchorStatus::Active),
        "disabled" => Ok(AnchorStatus::Disabled),
        other => Err(format!("anchor status must be active|disabled (got \"{other}\")").into()),
    }
}

fn key_status(text: Option<&str>) -> Result<KeyStatus, DynError> {
    match text.unwrap_or("active") {
        "staged" => Ok(KeyStatus::Staged),
        "active" => Ok(KeyStatus::Active),
        "retired" => Ok(KeyStatus::Retired),
        "revoked" => Ok(KeyStatus::Revoked),
        other => Err(
            format!("key status must be staged|active|retired|revoked (got \"{other}\")").into(),
        ),
    }
}

/// `routeloom-trust-image-spec-v1` → TrustImage. Numbers are u32/u8
/// fields; every 8-byte id is a 16-hex string; pubkeys are 128-hex,
/// kid fingerprints 64-hex. A provisioning-golden `trust-image` document
/// is accepted too — the golden files are the same fields plus hex
/// encodings, so a vector doubles as a spec.
fn trust_image_from_spec(doc: &Json) -> Result<TrustImage, DynError> {
    let format_ok = match doc.get("format").and_then(|v| v.as_str()) {
        Some("routeloom-trust-image-spec-v1") => true,
        Some("routeloom-provisioning-golden-v1") => {
            doc.get("kind").and_then(|v| v.as_str()) == Some("trust-image")
        }
        _ => false,
    };
    if !format_ok {
        return Err("spec format must be routeloom-trust-image-spec-v1".into());
    }
    let mut image = TrustImage {
        store_epoch: spec_u32(doc, "store_epoch")?,
        min_authority_generation: spec_u32(doc, "min_authority_generation")?,
        network: spec_id(doc, "network")?,
        deployment_id: spec_id(doc, "deployment_id")?,
        flags: spec_u8(doc, "flags").unwrap_or(0),
        ..TrustImage::default()
    };
    for entry in spec_array(doc, "anchors")? {
        image.anchors.push(TrustAnchor {
            root_id: spec_id(entry, "root_id")?,
            pubkey: spec_hex(entry, "pubkey_hex")?,
            status: anchor_status(entry.get("status").and_then(|v| v.as_str()))?,
        });
    }
    for entry in spec_array(doc, "keys")? {
        image.keys.push(TrustKeyRecord {
            authority_id: spec_id(entry, "authority_id")?,
            generation: spec_u32(entry, "generation")?,
            profile: spec_u8(entry, "profile").unwrap_or(1),
            role: spec_u8(entry, "role").unwrap_or(1),
            status: key_status(entry.get("status").and_then(|v| v.as_str()))?,
            scope: spec_u8(entry, "scope").unwrap_or(0),
            pubkey: spec_hex(entry, "pubkey_hex")?,
        });
    }
    for entry in spec_array(doc, "revocations")? {
        image.revocations.push(TrustRevocation {
            node_id: spec_id(entry, "node_id")?,
            kid_fingerprint: spec_hex(entry, "kid_hex")?,
            revoked_at_epoch: spec_u32(entry, "revoked_at_epoch")?,
            kind: spec_u8(entry, "kind").unwrap_or(1),
        });
    }
    Ok(image)
}

/// `routeloom-credential-spec-v1` → DeviceCredential. `secret_hex` is the
/// private scalar for `nvs-plaintext` (factory-injected keys are the
/// documented T1-lower option — on-device generation never produces a
/// spec file). kid is derived, never trusted from the document.
fn credential_from_spec(doc: &Json) -> Result<DeviceCredential, DynError> {
    if doc.get("format").and_then(|v| v.as_str()) != Some("routeloom-credential-spec-v1") {
        return Err("credential spec format must be routeloom-credential-spec-v1".into());
    }
    let key_location = match doc.get("key_location").and_then(|v| v.as_str()) {
        None | Some("nvs-plaintext") => KeyLocation::NvsPlaintext,
        Some("none") => KeyLocation::None,
        Some("efuse-ds-bound") => KeyLocation::EfuseDsBound,
        Some("secure-element") => KeyLocation::SecureElement,
        Some(other) => {
            return Err(format!(
                "key_location must be none|nvs-plaintext|efuse-ds-bound|secure-element (got \"{other}\")"
            )
            .into())
        }
    };
    let cred_status = match doc.get("cred_status").and_then(|v| v.as_str()) {
        None | Some("active") => CredStatus::Active,
        Some("pending-registration") => CredStatus::PendingRegistration,
        Some("suspended-local") => CredStatus::SuspendedLocal,
        Some(other) => {
            return Err(format!(
                "cred_status must be pending-registration|active|suspended-local (got \"{other}\")"
            )
            .into())
        }
    };
    let secret: [u8; 32] = match doc.get("secret_hex").and_then(|v| v.as_str()) {
        Some(text) => hex_decode_exact(text, 32)
            .ok_or("secret_hex must be 32 bytes hex")?
            .try_into()
            .expect("32"),
        None if key_location == KeyLocation::NvsPlaintext => {
            return Err("nvs-plaintext credential requires secret_hex".into())
        }
        None => [0_u8; 32],
    };
    let pubkey: [u8; 64] = match doc.get("pubkey_hex").and_then(|v| v.as_str()) {
        Some(text) => hex_decode_exact(text, 64)
            .ok_or("pubkey_hex must be 64 bytes hex")?
            .try_into()
            .expect("64"),
        None => routeloom_provision::signer::pubkey_from_secret(&secret)
            .ok_or("secret_hex is not a valid P-256 scalar")?,
    };
    let grant = match doc.get("grant_hex").and_then(|v| v.as_str()) {
        Some(text) => {
            if text.len() % 2 != 0
                || !text.bytes().all(|b| b.is_ascii_hexdigit())
                || text.len() > CREDENTIAL_GRANT_MAX * 2
            {
                return Err(format!(
                    "grant_hex must be even-length hex ≤ {CREDENTIAL_GRANT_MAX} bytes"
                )
                .into());
            }
            (0..text.len() / 2)
                .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
                .collect()
        }
        None => Vec::new(),
    };
    let credential = DeviceCredential {
        network: spec_id(doc, "network")?,
        node_id: spec_id(doc, "node_id")?,
        generation_base_session: spec_u32(doc, "generation_base_session").unwrap_or(0),
        key_location,
        cred_status,
        kid: credential_kid(&pubkey),
        pubkey,
        key_material: secret,
        grant,
    };
    // Full semantic check now — a spec that cannot decode on-device is a
    // tool-side error, not a manufactured wedge.
    routeloom_provision::credential::credential_validate(&credential)?;
    credential_record_encode(&credential, CRED_SEAL_COMMITTED)?;
    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_provision::signer::test_keypair;

    fn pubkey_hex(seed: u8) -> String {
        hex_encode(&test_keypair(seed).1)
    }

    fn image_spec(anchor_pub: &str, key_pub: &str) -> String {
        format!(
            r#"{{
  "format": "routeloom-trust-image-spec-v1",
  "store_epoch": 1,
  "min_authority_generation": 1,
  "network": "0000000000000007",
  "deployment_id": "0000000000000de9",
  "flags": 0,
  "anchors": [
    {{"root_id": "0000000000000100", "pubkey_hex": "{anchor_pub}", "status": "active"}}
  ],
  "keys": [
    {{"authority_id": "0000000000000a17", "generation": 1, "profile": 1, "role": 1, "status": "active", "scope": 0, "pubkey_hex": "{key_pub}"}}
  ],
  "revocations": []
}}"#
        )
    }

    #[test]
    fn image_spec_roundtrip() {
        let doc = routeloom_json::parse(&image_spec(&pubkey_hex(0x11), &pubkey_hex(0x33))).unwrap();
        let image = trust_image_from_spec(&doc).unwrap();
        image_validate(&image).unwrap();
        assert_eq!(image.store_epoch, 1);
        assert_eq!(image.network, 7);
        assert_eq!(image.anchors[0].root_id, 0x100);
        assert_eq!(image.keys[0].authority_id, 0xA17);
        // A committed record round-trips through load_image's RLT1 arm.
        let record = image_encode(&image, TRUST_SEAL_COMMITTED).unwrap();
        assert_eq!(image_decode(&record).unwrap(), image);
    }

    #[test]
    fn image_spec_rejections() {
        // Wrong format tag.
        let doc = routeloom_json::parse(r#"{"format":"other"}"#).unwrap();
        assert!(trust_image_from_spec(&doc).is_err());
        // Missing required numeric field.
        let doc =
            routeloom_json::parse(r#"{"format":"routeloom-trust-image-spec-v1","store_epoch":1}"#)
                .unwrap();
        assert!(trust_image_from_spec(&doc).is_err());
        // Off-curve anchor pubkey fails at image_validate (encode time).
        let doc = routeloom_json::parse(&image_spec(&"00".repeat(64), &pubkey_hex(0x33))).unwrap();
        let image = trust_image_from_spec(&doc).unwrap();
        assert!(image_validate(&image).is_err());
        // Bad status vocabulary.
        let bad = image_spec(&pubkey_hex(0x11), &pubkey_hex(0x33)).replacen(
            "\"status\": \"active\"",
            "\"status\": \"bogus\"",
            1,
        );
        assert!(bad.contains("bogus"));
        let doc = routeloom_json::parse(&bad).unwrap();
        assert!(trust_image_from_spec(&doc).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn nvs_output_is_private_and_refuses_existing_paths() {
        use std::os::unix::fs::PermissionsExt;
        let image = trust_image_from_spec(
            &routeloom_json::parse(&image_spec(&pubkey_hex(0x11), &pubkey_hex(0x33))).unwrap(),
        )
        .unwrap();
        let (secret, pubkey) = test_keypair(0x55);
        let credential = credential_from_spec(&routeloom_json::parse(&format!(
            r#"{{"format":"routeloom-credential-spec-v1","network":"0000000000000007","node_id":"00000000000000c3","generation_base_session":0,"key_location":"nvs-plaintext","cred_status":"active","secret_hex":"{}","pubkey_hex":"{}"}}"#,
            hex_encode(&secret), hex_encode(&pubkey),
        )).unwrap()).unwrap();
        let set = manufacture_nvs_set(&image, Some(&credential), 0).unwrap();
        assert!(set.descriptor_json().contains(&hex_encode(&secret)));
        let dir = std::env::temp_dir().join(format!(
            "routeloom-private-nvs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        write_private_nvs_set(&dir, &set).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in &set.entries {
            assert_eq!(
                std::fs::metadata(dir.join(entry.file_name()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            std::fs::metadata(dir.join("nvs-set.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(write_private_nvs_set(&dir, &set).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(write_private_nvs_set(&dir, &set).is_err());
        std::fs::remove_dir(&dir).unwrap();

        let nested = dir.join("new-parent").join("nvs");
        write_private_nvs_set(&nested, &set).unwrap();
        assert_eq!(
            std::fs::metadata(nested.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn credential_spec_paths() {
        let (secret, pubkey) = test_keypair(0x55);
        let spec = format!(
            r#"{{
  "format": "routeloom-credential-spec-v1",
  "network": "0000000000000007",
  "node_id": "00000000000000c3",
  "generation_base_session": 0,
  "key_location": "nvs-plaintext",
  "cred_status": "active",
  "secret_hex": "{}",
  "pubkey_hex": "{}"
}}"#,
            hex_encode(&secret),
            hex_encode(&pubkey),
        );
        let doc = routeloom_json::parse(&spec).unwrap();
        let credential = credential_from_spec(&doc).unwrap();
        assert_eq!(credential.node_id, 0xC3);
        assert_eq!(credential.kid, credential_kid(&credential.pubkey));
        // kid is derived, so a spec naming a mismatched pubkey/secret pair
        // is refused by credential_validate's consistency check.
        let mismatched = spec.replace(&hex_encode(&pubkey), &hex_encode(&test_keypair(0x66).1));
        let doc = routeloom_json::parse(&mismatched).unwrap();
        assert!(credential_from_spec(&doc).is_err());
        // nvs-plaintext without secret material is refused.
        let no_secret = spec.replace(&format!("\"secret_hex\": \"{}\",", hex_encode(&secret)), "");
        let doc = routeloom_json::parse(&no_secret).unwrap();
        assert!(credential_from_spec(&doc).is_err());
    }
}
