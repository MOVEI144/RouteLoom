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
//!
//! Issuance is ledger-backed and atomic (P1-2/P2-4): every run reserves
//! its (Device CA, NodeId, serial) slot in the office ledger before
//! minting anything, stages all output files to a sibling temp directory,
//! verifies them, then publishes with one atomic rename. Re-running the
//! same work resumes (staging is reused, a published output is adopted);
//! any other work on a reserved slot refuses.

use std::path::{Path, PathBuf};

use routeloom_json::Json;

use crate::office_ledger::{
    default_work_id, staging_dir, staging_key_file, IssueSlot, LedgerStatus, OfficeLedger,
    ReserveOutcome,
};
use crate::{is_hex, opt_value};

use routeloom_provision::credential::{credential_kid, KeyLocation};
use routeloom_provision::sdkv1::cert::{cert_decode, CertType};
use routeloom_provision::sdkv1::devca::{
    devcert_issue, devcert_verify, DevCertProfile, DeviceCaSigner, FileDeviceCaSigner,
    DEVICE_CA_CUSTODY_WARNING,
};
use routeloom_provision::sdkv1::identity::{
    identity_record_decode, identity_record_encode, AnchorKind, AnchorStatus, IdentityAnchor,
    IDENTITY_SEAL_COMMITTED,
};
use routeloom_provision::sdkv1::office::{
    identity_build_injected, identity_bundle_json, inventory_file_json, inventory_json,
    IdentityPlan, OFFICE_STATUS_ISSUED, OFFICE_STATUS_WRITTEN,
};
use routeloom_provision::sdkv1::pop::{
    pop_challenge, pop_sign, pop_verify, POP_CHALLENGE_SIZE, POP_OBJECT_SIZE,
};
use routeloom_provision::sdkv1::rlsec::{rlsec_identity_readback, rlsec_identity_set};
use routeloom_provision::sdkv1::siteca::{
    sitecert_issue, FileSiteCaSigner, SiteCaSigner, SiteCertProfile, SITE_CA_CUSTODY_WARNING,
};
use routeloom_provision::signer::{
    generate_keypair, hex_decode_exact, hex_encode, pubkey_from_secret, write_private_file,
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
/// --out-dir <dir> [--ledger <file>] [--work-id <id>]` — verify the
/// device's proof of possession for exactly this node and challenge,
/// reserve the ledger slot, issue the DevCert, and publish `devcert.cwt`,
/// `identity-bundle.json` (no secret) and `inventory.json` atomically.
/// Prints the inventory line.
pub fn provision_devcert_command(args: &[String]) -> Result<(), DynError> {
    let mut opts = OfficeOptions::parse("provision-devcert", args, &["--challenge", "--pop"])?;
    let challenge_hex = opts.take("--challenge")?;
    let challenge: [u8; POP_CHALLENGE_SIZE] = hex_decode_exact(&challenge_hex, POP_CHALLENGE_SIZE)
        .ok_or("--challenge must be 64 hex")?
        .try_into()
        .expect("32 bytes");
    let pop_path = PathBuf::from(opts.take("--pop")?);
    let pop = read_object(&pop_path, POP_OBJECT_SIZE)?;
    eprintln!("{DEVICE_CA_CUSTODY_WARNING}");
    let output = run_provision_devcert(&IssuanceInputs::from_options(&opts)?, &challenge, &pop)?;
    println!("{}", output.inventory_line);
    Ok(())
}

/// `provision-identity --ca-key <devca.key> --spec <identity-spec.json>
/// --node <16hex> --serial <u32> --out-dir <dir> [--ledger <file>]
/// [--work-id <id>]` — injected-key path: reserve the ledger slot, key
/// generated here, proof of possession made and checked like a device's,
/// DevCert issued, RLI1 built and read back, and the `rlsec` NVS set
/// staged (`nvs_partition_gen.py` CSV + blobs) and published atomically,
/// plus `inventory.json`. Prints the inventory line.
pub fn provision_identity_command(args: &[String]) -> Result<(), DynError> {
    let opts = OfficeOptions::parse("provision-identity", args, &[])?;
    eprintln!("{DEVICE_CA_CUSTODY_WARNING}");
    let output = run_provision_identity(&IssuanceInputs::from_options(&opts)?)?;
    eprintln!("{INJECTED_KEY_WARNING}");
    println!("{}", output.inventory_line);
    Ok(())
}

// --- ledger-backed atomic issuance -------------------------------------------------

/// The published file set per key path.
const DEVCERT_FILES: [&str; 3] = ["devcert.cwt", "identity-bundle.json", "inventory.json"];
const IDENTITY_FILES: [&str; 7] = [
    "devcert.cwt",
    "inventory.json",
    "identity.rli1",
    "rlident_i0.bin",
    "rlident_i1.bin",
    "rlsec-nvs.csv",
    "rlsec-set.json",
];

/// What one issuance run publishes (printed by the CLI wrapper).
struct IssuedOutput {
    devcert: Vec<u8>,
    inventory_line: String,
}

/// The ledger-backed issuance inputs shared by both key paths.
struct IssuanceInputs {
    ledger: OfficeLedger,
    work_id: String,
    out_dir: PathBuf,
    node: u64,
    serial: u32,
    device_ca_id: u64,
    plan: IdentityPlan,
    profile: DevCertProfile,
    signer: FileDeviceCaSigner,
}

impl IssuanceInputs {
    fn from_options(opts: &OfficeOptions) -> Result<Self, DynError> {
        let signer = FileDeviceCaSigner::load(&opts.ca_key)?;
        let ledger_path = opts.ledger.clone().unwrap_or_else(|| {
            opts.ca_key
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("office-ledger.jsonl")
        });
        Ok(Self {
            ledger: OfficeLedger::open(&ledger_path)?,
            work_id: opts
                .work_id
                .clone()
                .unwrap_or_else(|| default_work_id(&opts.out_dir)),
            out_dir: opts.out_dir.clone(),
            node: opts.node,
            serial: opts.profile.serial,
            device_ca_id: signer.device_ca_id(),
            plan: opts.plan.clone(),
            profile: opts.profile,
            signer,
        })
    }

    fn out_dir_text(&self) -> String {
        default_work_id(&self.out_dir)
    }

    fn slot(&self) -> IssueSlot {
        IssueSlot {
            device_ca_id: self.device_ca_id,
            node_id: self.node,
            serial: self.serial,
        }
    }
}

fn run_provision_devcert(
    inputs: &IssuanceInputs,
    challenge: &[u8; POP_CHALLENGE_SIZE],
    pop: &[u8],
) -> Result<IssuedOutput, DynError> {
    let _work = OfficeLedger::lock_work(&staging_dir(&inputs.out_dir, &inputs.work_id))?;
    let key = pop_verify(pop, inputs.node, challenge)
        .map_err(|e| format!("proof of possession refused: {e}"))?;
    let kid = credential_kid(&key.pubkey());
    let outcome = inputs
        .ledger
        .reserve(
            inputs.slot(),
            Some(kid),
            &inputs.work_id,
            &inputs.out_dir_text(),
        )
        .map_err(|e| format!("ledger reservation refused: {e}"))?;
    // The PoP inputs are the caller's bytes: a resumed work recomputes
    // the same DevCert from them, so staging always rebuilds fresh.
    let stage = |staging: &Path| -> Result<(), DynError> {
        let devcert = devcert_issue(&inputs.signer, &key, &inputs.profile)?;
        let bundle = identity_bundle_json(&inputs.plan, &devcert)?;
        std::fs::create_dir_all(staging)?;
        write_new(&staging.join("devcert.cwt"), &devcert)?;
        write_new(&staging.join("identity-bundle.json"), bundle.as_bytes())?;
        write_new(
            &staging.join("inventory.json"),
            inventory_file_json(&devcert, OFFICE_STATUS_ISSUED)?.as_bytes(),
        )?;
        Ok(())
    };
    publish_work(inputs, &DEVCERT_FILES, false, &stage, &outcome)
}

fn run_provision_identity(inputs: &IssuanceInputs) -> Result<IssuedOutput, DynError> {
    let staging = staging_dir(&inputs.out_dir, &inputs.work_id);
    let escrow = staging_key_file(&staging);
    let _work = OfficeLedger::lock_work(&staging)?;
    let outcome = inputs
        .ledger
        .reserve(inputs.slot(), None, &inputs.work_id, &inputs.out_dir_text())
        .map_err(|e| format!("ledger reservation refused: {e}"))?;
    // A crashed run's staging still holds its key: resume reuses it
    // instead of minting a second key for the same slot. Anything else
    // in staging fails closed — staging is this work's temp area, and a
    // foreign RLI1 there is never silently adopted.
    let reused = reuse_staged_key(inputs)?;
    // The published output, when intact, adopts without minting (see
    // publish_work): the already-issued guard below only bites when this
    // run would actually stage fresh material.
    let out_intact = inputs.out_dir.is_dir()
        && directory_matches(&inputs.out_dir, &IDENTITY_FILES, inputs).unwrap_or(false);
    if inputs.out_dir.exists() && !out_intact {
        return Err(format!(
            "{} exists and is not this work's complete output",
            inputs.out_dir.display()
        )
        .into());
    }
    if !out_intact {
        if let ReserveOutcome::Resume(entry) = &outcome {
            if let Some(issued_kid) = entry.kid {
                // Already issued: only a resume carrying the SAME key may
                // proceed (recreating a lost output); never mint a second
                // key. Refuse before minting, not after publishing.
                match reused {
                    Some((_, staged_kid)) if staged_kid == issued_kid => {}
                    Some(_) => {
                        return Err(format!(
                        "node {:016x} serial {} is already issued for another device key; refusing a key swap",
                        inputs.node, inputs.serial
                    )
                    .into());
                    }
                    None => {
                        return Err(format!(
                        "node {:016x} serial {} is already issued; refusing to mint a second key (restore {} or issue a new NodeId)",
                        inputs.node,
                        inputs.serial,
                        inputs.out_dir.display()
                    )
                    .into());
                    }
                }
            }
        }
    }
    // Persist the key before signing a DevCert. A crash after signing but
    // before RLI1 assembly can then retry with the same device identity.
    let selected = if out_intact {
        reused
    } else {
        match reused {
            Some(key) => Some(key),
            None => {
                let (secret, pubkey) = generate_keypair()?;
                write_private_file(&escrow, &secret)?;
                sync_path(&escrow)?;
                sync_path(escrow.parent().unwrap_or(Path::new(".")))?;
                Some((secret, credential_kid(&pubkey)))
            }
        }
    };
    if !out_intact {
        let kid = selected.ok_or("staged key is unavailable")?.1;
        inputs.ledger.reserve(
            inputs.slot(),
            Some(kid),
            &inputs.work_id,
            &inputs.out_dir_text(),
        )?;
    }
    let stage = |staging: &Path| -> Result<(), DynError> {
        let secret = selected.ok_or("staged key is unavailable")?.0;
        let challenge = pop_challenge()?;
        let pop = pop_sign(&secret, inputs.node, KeyLocation::NvsPlaintext, &challenge)?;
        let key = pop_verify(&pop, inputs.node, &challenge)?;
        let devcert = devcert_issue(&inputs.signer, &key, &inputs.profile)?;
        let record = identity_build_injected(&inputs.plan, &secret, &devcert)?;
        let set = rlsec_identity_set(&record)?;
        if rlsec_identity_readback(&set)? != record {
            return Err("rlsec set does not read back as the built identity".into());
        }
        write_new(&staging.join("devcert.cwt"), &devcert)?;
        write_new(
            &staging.join("inventory.json"),
            inventory_file_json(&devcert, OFFICE_STATUS_ISSUED)?.as_bytes(),
        )?;
        write_private_file(
            &staging.join("identity.rli1"),
            &identity_record_encode(&record, IDENTITY_SEAL_COMMITTED)?,
        )?;
        for entry in &set.entries {
            write_private_file(&staging.join(entry.file_name()), &entry.bytes())?;
        }
        write_new(
            &staging.join("rlsec-nvs.csv"),
            set.partition_csv().as_bytes(),
        )?;
        write_private_file(
            &staging.join("rlsec-set.json"),
            set.descriptor_json().as_bytes(),
        )?;
        Ok(())
    };
    let output = publish_work(inputs, &IDENTITY_FILES, true, &stage, &outcome)?;
    match std::fs::remove_file(&escrow) {
        Ok(()) => sync_path(escrow.parent().unwrap_or(Path::new(".")))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(output)
}

/// A staged key: the secret plus the kid it was staged under.
type StagedKey = ([u8; 32], [u8; 32]);

/// Read a crashed run's staged key for reuse (injected path only).
fn reuse_staged_key(inputs: &IssuanceInputs) -> Result<Option<StagedKey>, DynError> {
    let staging = staging_dir(&inputs.out_dir, &inputs.work_id);
    let escrow = staging_key_file(&staging);
    let staged = staging.join("identity.rli1");
    let saved = match std::fs::read(&escrow) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(format!("{}: invalid staged key length", escrow.display()).into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::metadata(&escrow)?.permissions().mode() & 0o077 != 0 {
                    return Err(format!("{}: staged key is not private", escrow.display()).into());
                }
            }
            let secret: [u8; 32] = bytes.try_into().expect("32 bytes");
            let pubkey = pubkey_from_secret(&secret).ok_or("staged key is invalid")?;
            Some((secret, credential_kid(&pubkey)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", escrow.display()).into()),
    };
    let bytes = match std::fs::read(&staged) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if saved.is_none() && staging.exists() && std::fs::read_dir(&staging)?.next().is_some()
            {
                return Err("staging contains issuance data but its device key is unavailable; use a new NodeId".into());
            }
            return Ok(saved);
        }
        Err(e) => return Err(format!("{}: {e}", staged.display()).into()),
    };
    let record = identity_record_decode(&bytes)
        .map_err(|e| format!("staged identity.rli1 is corrupt: {e}"))?;
    if record.node_id != inputs.node {
        return Err(format!(
            "staged identity.rli1 names node {:016x}, not {:016x}; refusing to mix works",
            record.node_id, inputs.node
        )
        .into());
    }
    if let Some((secret, kid)) = saved {
        if record.key_material != secret || record.kid != kid {
            return Err("staged identity does not match its saved device key".into());
        }
        return Ok(Some((secret, kid)));
    }
    write_private_file(&escrow, &record.key_material)?;
    sync_path(&escrow)?;
    sync_path(escrow.parent().unwrap_or(Path::new(".")))?;
    Ok(Some((record.key_material, record.kid)))
}

/// Stage (fresh temp dir), verify, publish with one atomic rename.
/// Re-running the same work adopts its published output; any other
/// occupant of the out directory refuses.
fn publish_work(
    inputs: &IssuanceInputs,
    expected: &[&str],
    owner_only: bool,
    stage: &dyn Fn(&Path) -> Result<(), DynError>,
    outcome: &ReserveOutcome,
) -> Result<IssuedOutput, DynError> {
    let staging = staging_dir(&inputs.out_dir, &inputs.work_id);
    if inputs.out_dir.exists() {
        if matches!(outcome, ReserveOutcome::Resume(_))
            && directory_matches(&inputs.out_dir, expected, inputs)?
        {
            // Adopt: this work already published (a crash after the
            // rename, or a plain re-run). The ledger mark retries here,
            // so a crash between publish and mark heals on re-run.
            let _ = std::fs::remove_dir_all(&staging);
            return adopted_output(inputs);
        }
        return Err(format!(
            "{} exists and is not this work's published output (refusing to overwrite)",
            inputs.out_dir.display()
        )
        .into());
    }
    let _ = std::fs::remove_dir_all(&staging);
    if owner_only {
        // The directory holds the device secret: owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&staging)?;
        }
        #[cfg(windows)]
        {
            routeloom_peercred::create_private_dir_all(&staging)?;
        }
    } else {
        std::fs::create_dir_all(&staging)?;
    }
    stage(&staging)?;
    if !directory_matches(&staging, expected, inputs)? {
        return Err("staged issuance does not verify; refusing to publish".into());
    }
    let (staged_kid, staged_digest) = published_identity(&staging)?;
    if let ReserveOutcome::Resume(entry) = outcome {
        if entry.kid.is_some_and(|kid| kid != staged_kid)
            || (matches!(entry.status, LedgerStatus::Issued | LedgerStatus::Written)
                && entry.devcert_sha256 != Some(staged_digest))
        {
            return Err(
                "staged issuance differs from the ledger's bound key or issued DevCert".into(),
            );
        }
    }
    for name in expected {
        sync_path(&staging.join(name))?;
    }
    sync_path(&staging)?;
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &staging,
            rustix::fs::CWD,
            &inputs.out_dir,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|e| format!("publish {}: {e}", inputs.out_dir.display()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        routeloom_peercred::publish_dir_noreplace(&staging, &inputs.out_dir)
            .map_err(|e| format!("publish {}: {e}", inputs.out_dir.display()))?;
    }
    if let Some(parent) = inputs.out_dir.parent() {
        sync_path(parent)?;
    }
    // The kid and digest are re-read from the published output, never
    // from the RAM that wrote it.
    let (kid, digest) = published_identity(&inputs.out_dir)?;
    inputs.ledger.mark_issued(
        inputs.slot(),
        kid,
        digest,
        &inputs.work_id,
        &inputs.out_dir_text(),
    )?;
    adopted_output(inputs)
}

/// The already-published output of this work, re-read from disk.
fn adopted_output(inputs: &IssuanceInputs) -> Result<IssuedOutput, DynError> {
    let devcert = std::fs::read(inputs.out_dir.join("devcert.cwt"))?;
    let inventory_line = inventory_json(&devcert)?;
    let claims =
        cert_decode(&devcert).map_err(|e| format!("published devcert.cwt is corrupt: {e}"))?;
    inputs.ledger.mark_issued(
        inputs.slot(),
        credential_kid(&claims.pubkey),
        routeloom_provision::sha256::sha256(&devcert),
        &inputs.work_id,
        &inputs.out_dir_text(),
    )?;
    Ok(IssuedOutput {
        devcert,
        inventory_line,
    })
}

/// A directory holds this work's output only when its entire published
/// file set matches the DevCert, plan, inventory and NVS readback.
fn directory_matches(
    dir: &Path,
    expected: &[&str],
    inputs: &IssuanceInputs,
) -> Result<bool, DynError> {
    for name in expected {
        if !dir.join(name).is_file() {
            return Ok(false);
        }
    }
    let devcert = std::fs::read(dir.join("devcert.cwt"))?;
    let claims = match devcert_verify(&devcert, inputs.device_ca_id, &inputs.signer.pubkey()) {
        Ok(claims) => claims,
        Err(_) => return Ok(false),
    };
    if claims.cert_type != CertType::Device
        || claims.subject != inputs.node
        || claims.serial != inputs.serial
        || claims.issuer != inputs.device_ca_id
        || claims.model != inputs.profile.model
        || claims.hw_rev != inputs.profile.hw_rev
    {
        return Ok(false);
    }
    let inventory = std::fs::read(dir.join("inventory.json"))?;
    if inventory != inventory_file_json(&devcert, OFFICE_STATUS_ISSUED)?.as_bytes()
        && inventory != inventory_file_json(&devcert, OFFICE_STATUS_WRITTEN)?.as_bytes()
    {
        return Ok(false);
    }
    if expected == DEVCERT_FILES {
        return Ok(std::fs::read(dir.join("identity-bundle.json"))?
            == identity_bundle_json(&inputs.plan, &devcert)?.as_bytes());
    }
    if expected != IDENTITY_FILES {
        return Ok(false);
    }
    let identity = std::fs::read(dir.join("identity.rli1"))?;
    let record = match identity_record_decode(&identity) {
        Ok(record) => record,
        Err(_) => return Ok(false),
    };
    if record.node_id != inputs.node
        || record.flags != inputs.plan.flags
        || record.anchors != inputs.plan.anchors
        || record.devcert != devcert
        || record.key_location != KeyLocation::NvsPlaintext
        || record.kid != credential_kid(&claims.pubkey)
    {
        return Ok(false);
    }
    if std::fs::read(dir.join("rlident_i0.bin"))? != identity
        || std::fs::read(dir.join("rlident_i1.bin"))? != identity
    {
        return Ok(false);
    }
    let set = rlsec_identity_set(&record)?;
    if std::fs::read(dir.join("rlsec-nvs.csv"))? != set.partition_csv().as_bytes()
        || std::fs::read(dir.join("rlsec-set.json"))? != set.descriptor_json().as_bytes()
    {
        return Ok(false);
    }
    #[cfg(any(unix, windows))]
    {
        if routeloom_peercred::verify_private_dir_perms(dir).is_err() {
            return Ok(false);
        }
        for name in [
            "identity.rli1",
            "rlident_i0.bin",
            "rlident_i1.bin",
            "rlsec-set.json",
        ] {
            if routeloom_peercred::verify_private_file_perms(&dir.join(name)).is_err() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn published_identity(out_dir: &Path) -> Result<([u8; 32], [u8; 32]), DynError> {
    let devcert = std::fs::read(out_dir.join("devcert.cwt"))?;
    let claims =
        cert_decode(&devcert).map_err(|e| format!("published devcert.cwt is corrupt: {e}"))?;
    Ok((
        credential_kid(&claims.pubkey),
        routeloom_provision::sha256::sha256(&devcert),
    ))
}

fn sync_path(path: &Path) -> Result<(), DynError> {
    #[cfg(windows)]
    if path.is_dir() {
        return Ok(());
    }
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("{}: {e}", path.display()))?;
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

// --- ledger operations -------------------------------------------------------------

/// `provision-ledger-status --ledger <file>` — dump the folded ledger
/// (one entry per issuance slot, sorted by node).
pub fn provision_ledger_status_command(args: &[String]) -> Result<(), DynError> {
    let mut ledger: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ledger" => ledger = Some(opt_value(&mut args, "--ledger")?),
            other => {
                return Err(format!("unknown provision-ledger-status option: {other}").into());
            }
        }
    }
    let ledger = OfficeLedger::open(&PathBuf::from(
        ledger.ok_or("provision-ledger-status requires --ledger <file>")?,
    ))?;
    println!("{}", ledger_status_json(&ledger)?);
    Ok(())
}

fn ledger_status_json(ledger: &OfficeLedger) -> Result<String, DynError> {
    let mut entries = ledger.entries()?;
    entries.sort_by_key(|e| (e.node_id, e.serial));
    let mut out = String::from("{\"entries\":[");
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"device_ca_id\":\"{:016x}\",\"node_id\":\"{:016x}\",\"serial\":{},\"kid\":\"{}\",\"devcert_sha256\":\"{}\",\"work_id\":\"{}\",\"out_dir\":\"{}\",\"status\":\"{}\",\"ts\":{}}}",
            entry.device_ca_id,
            entry.node_id,
            entry.serial,
            entry.kid.map(|k| hex_encode(&k)).unwrap_or_default(),
            entry
                .devcert_sha256
                .map(|d| hex_encode(&d))
                .unwrap_or_default(),
            routeloom_json::escape_string(&entry.work_id),
            routeloom_json::escape_string(&entry.out_dir),
            entry.status.name(),
            entry.ts,
        ));
    }
    out.push_str("]}");
    Ok(out)
}

/// `provision-ledger-release --ledger <file> --node <16hex> --serial
/// <u32> --work-id <id>` — drop an abandoned `reserved` entry after verifying
/// the work has no output, staging or saved device key. Issued history is
/// never released.
pub fn provision_ledger_release_command(args: &[String]) -> Result<(), DynError> {
    let mut ledger: Option<String> = None;
    let mut node: Option<String> = None;
    let mut serial: Option<String> = None;
    let mut work_id: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ledger" => ledger = Some(opt_value(&mut args, "--ledger")?),
            "--node" => node = Some(opt_value(&mut args, "--node")?),
            "--serial" => serial = Some(opt_value(&mut args, "--serial")?),
            "--work-id" => work_id = Some(opt_value(&mut args, "--work-id")?),
            other => {
                return Err(format!("unknown provision-ledger-release option: {other}").into());
            }
        }
    }
    let node = node_id(&node.ok_or("provision-ledger-release requires --node <16hex>")?)?;
    let serial: u32 = serial
        .ok_or("provision-ledger-release requires --serial <u32>")?
        .parse()
        .map_err(|_| "--serial must be a u32")?;
    let work_id = work_id.ok_or("provision-ledger-release requires --work-id <id>")?;
    let ledger = OfficeLedger::open(&PathBuf::from(
        ledger.ok_or("provision-ledger-release requires --ledger <file>")?,
    ))?;
    let _released = ledger.release(node, serial, &work_id)?;
    println!(
        "{{\"released\":{{\"node_id\":\"{node:016x}\",\"serial\":{serial},\"work_id\":\"{}\"}}}}",
        routeloom_json::escape_string(&work_id)
    );
    Ok(())
}

/// `provision-ledger-import --ledger <file> --out-dir <dir> [--work-id
/// <id>]` — adopt a pre-ledger published output into the ledger, so an
/// upgrade from unledgered tooling cannot reissue its slot. The kid and
/// digest are read from the directory's own DevCert.
pub fn provision_ledger_import_command(args: &[String]) -> Result<(), DynError> {
    let mut ledger: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut work_id: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ledger" => ledger = Some(opt_value(&mut args, "--ledger")?),
            "--out-dir" => out_dir = Some(opt_value(&mut args, "--out-dir")?),
            "--work-id" => work_id = Some(opt_value(&mut args, "--work-id")?),
            other => {
                return Err(format!("unknown provision-ledger-import option: {other}").into());
            }
        }
    }
    let out_dir = PathBuf::from(out_dir.ok_or("provision-ledger-import requires --out-dir <dir>")?);
    let expected: &[&str] = if out_dir.join("identity.rli1").is_file() {
        &IDENTITY_FILES
    } else {
        &DEVCERT_FILES
    };
    for name in expected {
        if !out_dir.join(name).is_file() {
            return Err(format!(
                "{} is not a complete published output (missing {name}); refusing to import",
                out_dir.display()
            )
            .into());
        }
    }
    let devcert = std::fs::read(out_dir.join("devcert.cwt"))?;
    let claims = cert_decode(&devcert).map_err(|e| format!("devcert.cwt does not decode: {e}"))?;
    if claims.cert_type != CertType::Device {
        return Err("devcert.cwt is not a DevCert; refusing to import".into());
    }
    let work_id = work_id.unwrap_or_else(|| default_work_id(&out_dir));
    let kid = credential_kid(&claims.pubkey);
    let digest = routeloom_provision::sha256::sha256(&devcert);
    let ledger = OfficeLedger::open(&PathBuf::from(
        ledger.ok_or("provision-ledger-import requires --ledger <file>")?,
    ))?;
    let slot = IssueSlot {
        device_ca_id: claims.issuer,
        node_id: claims.subject,
        serial: claims.serial,
    };
    ledger
        .reserve(slot, Some(kid), &work_id, &out_dir.to_string_lossy())
        .map_err(|e| format!("ledger reservation refused: {e}"))?;
    ledger.mark_issued(slot, kid, digest, &work_id, &out_dir.to_string_lossy())?;
    println!(
        "{{\"imported\":{{\"node_id\":\"{:016x}\",\"serial\":{},\"work_id\":\"{}\"}}}}",
        claims.subject,
        claims.serial,
        routeloom_json::escape_string(&work_id)
    );
    Ok(())
}

/// `provision-confirm-written --ledger <file> --node <16hex>
/// --devcert-sha256 <64hex> [--out-dir <dir>]` — match the device's
/// console receipt (`status` → `devcert_sha256`) against the office
/// issuance and record the written confirmation. A mismatch refuses: it
/// is a USB mixup or a wrong device, never a typo to override. With
/// `--out-dir`, the directory is cross-checked too and its
/// `inventory.json` flips to `written`.
pub fn provision_confirm_written_command(args: &[String]) -> Result<(), DynError> {
    let mut ledger: Option<String> = None;
    let mut node: Option<String> = None;
    let mut digest: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ledger" => ledger = Some(opt_value(&mut args, "--ledger")?),
            "--node" => node = Some(opt_value(&mut args, "--node")?),
            "--devcert-sha256" => digest = Some(opt_value(&mut args, "--devcert-sha256")?),
            "--out-dir" => out_dir = Some(opt_value(&mut args, "--out-dir")?),
            other => {
                return Err(format!("unknown provision-confirm-written option: {other}").into());
            }
        }
    }
    let node = node_id(&node.ok_or("provision-confirm-written requires --node <16hex>")?)?;
    let want: [u8; 32] = hex_decode_exact(
        &digest.ok_or("provision-confirm-written requires --devcert-sha256 <64hex>")?,
        32,
    )
    .ok_or("--devcert-sha256 must be 64 hex")?
    .try_into()
    .expect("32 bytes");
    let ledger = OfficeLedger::open(&PathBuf::from(
        ledger.ok_or("provision-confirm-written requires --ledger <file>")?,
    ))?;
    let entry = ledger
        .entries()?
        .into_iter()
        .find(|e| e.node_id == node)
        .ok_or_else(|| format!("node {node:016x} has no ledger entry"))?;
    let Some(recorded) = entry.devcert_sha256 else {
        return Err(format!(
            "node {node:016x} was never issued; confirm a publish, not a reservation"
        )
        .into());
    };
    if recorded != want {
        return Err(format!(
            "device receipt does not match the office issuance for node {node:016x} (serial {}); refusing — check for a USB mixup before retrying",
            entry.serial
        )
        .into());
    }
    if let Some(out) = &out_dir {
        let out = PathBuf::from(out);
        let devcert = std::fs::read(out.join("devcert.cwt"))
            .map_err(|e| format!("{}: {e}", out.join("devcert.cwt").display()))?;
        if routeloom_provision::sha256::sha256(&devcert) != want {
            return Err(format!("{} holds another issuance; refusing", out.display()).into());
        }
        let inventory = inventory_file_json(&devcert, OFFICE_STATUS_WRITTEN)?;
        let tmp = out.join(format!("inventory.json.tmp-{}", std::process::id()));
        std::fs::write(&tmp, inventory.as_bytes())?;
        std::fs::rename(&tmp, out.join("inventory.json"))?;
    }
    ledger.mark_written(IssueSlot {
        device_ca_id: entry.device_ca_id,
        node_id: entry.node_id,
        serial: entry.serial,
    })?;
    println!(
        "{{\"node_id\":\"{node:016x}\",\"serial\":{},\"office_status\":\"written\"}}",
        entry.serial
    );
    Ok(())
}

/// `provision-expect --out-dir <dir>` — print the console `status` line
/// the sealed device MUST answer (matched after sealing, before `lock`),
/// plus the `lock` kid. Fails on an incomplete or mixed directory.
pub fn provision_expect_command(args: &[String]) -> Result<(), DynError> {
    let mut out_dir: Option<String> = None;
    let mut fw: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => out_dir = Some(opt_value(&mut args, "--out-dir")?),
            "--fw" => fw = Some(opt_value(&mut args, "--fw")?),
            other => return Err(format!("unknown provision-expect option: {other}").into()),
        }
    }
    let out = PathBuf::from(out_dir.ok_or("provision-expect requires --out-dir <dir>")?);
    let (status, lock_kid, office_status) = expect_sheet(&out, fw.as_deref())?;
    println!("expected_status: {status}");
    println!("lock_kid: {lock_kid}");
    println!("inventory_office_status: {office_status}");
    Ok(())
}

/// The matching sheet for one published output: the console `status`
/// line the sealed device must answer, the `lock` kid, and the
/// inventory's office state.
fn expect_sheet(out_dir: &Path, fw: Option<&str>) -> Result<(String, String, String), DynError> {
    // The version rule mirrors the console's `status` receipt
    // (sdkv1_maintenance): a version the device would report as
    // `unknown` refuses here, so the printed line always byte-matches a
    // healthy device or the command fails instead of mis-matching.
    if let Some(fw) = fw {
        if fw.is_empty() || fw.len() > 32 || !fw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err("provision-expect --fw must be 1..=32 printable ASCII bytes".into());
        }
    }
    let devcert = std::fs::read(out_dir.join("devcert.cwt")).map_err(|_| {
        format!(
            "{} has no devcert.cwt (not a published issuance?)",
            out_dir.display()
        )
    })?;
    let claims = cert_decode(&devcert).map_err(|e| format!("devcert.cwt does not decode: {e}"))?;
    if claims.cert_type != CertType::Device {
        return Err("devcert.cwt is not a DevCert".into());
    }
    let mut office_status = "unknown".to_string();
    if let Ok(text) = std::fs::read_to_string(out_dir.join("inventory.json")) {
        let inventory = routeloom_json::parse(&text).map_err(|e| format!("inventory.json: {e}"))?;
        if inventory.get("node_id").and_then(|v| v.as_str())
            != Some(format!("{:016x}", claims.subject).as_str())
        {
            return Err("inventory.json names another node; refusing a mixed directory".into());
        }
        if inventory.get("cert_serial").and_then(|v| v.as_u64()) != Some(u64::from(claims.serial)) {
            return Err("inventory.json names another serial; refusing a mixed directory".into());
        }
        office_status = inventory
            .get("office_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
    }
    let kid = credential_kid(&claims.pubkey);
    let digest = routeloom_provision::sha256::sha256(&devcert);
    let mut status = format!(
        "OK identity=sealed pending=0 locked=0 node={:016x} kid={} serial={} devcert_sha256={}",
        claims.subject,
        hex_encode(&kid),
        claims.serial,
        hex_encode(&digest)
    );
    if let Some(fw) = fw {
        status.push_str(" fw=");
        status.push_str(fw);
    }
    Ok((status, hex_encode(&kid), office_status))
}

/// `provision-batch --ca-key <key> --spec <spec> --ledger <path> --csv
/// <file> --out-root <dir> [--mode injected|devcert]` — issue many
/// devices in one run. Rows are `node,serial[,work_id]` (injected) or
/// `node,serial,challenge_hex,pop_hex[,work_id]` (devcert, the default:
/// challenges come from `provision-pop-challenge`, pops from the
/// devices' sweep). Each row issues into `<out-root>/<node>` through
/// the same ledger-backed atomic path; one row's failure never stops
/// the batch. Writes `<out-root>/batch-report.jsonl` (per-row
/// kid/digest for the later `provision-confirm-written` matching) and
/// fails the command when any row fails.
pub fn provision_batch_command(args: &[String]) -> Result<(), DynError> {
    let mut ca_key: Option<String> = None;
    let mut spec: Option<String> = None;
    let mut ledger: Option<String> = None;
    let mut csv: Option<String> = None;
    let mut out_root: Option<String> = None;
    let mut mode = String::from("devcert");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ca-key" => ca_key = Some(opt_value(&mut args, "--ca-key")?),
            "--spec" => spec = Some(opt_value(&mut args, "--spec")?),
            "--ledger" => ledger = Some(opt_value(&mut args, "--ledger")?),
            "--csv" => csv = Some(opt_value(&mut args, "--csv")?),
            "--out-root" => out_root = Some(opt_value(&mut args, "--out-root")?),
            "--mode" => mode = opt_value(&mut args, "--mode")?,
            other => return Err(format!("unknown provision-batch option: {other}").into()),
        }
    }
    if mode != "injected" && mode != "devcert" {
        return Err("--mode must be injected|devcert".into());
    }
    let ca_key = PathBuf::from(ca_key.ok_or("provision-batch requires --ca-key <file>")?);
    let spec = PathBuf::from(spec.ok_or("provision-batch requires --spec <file>")?);
    let spec_json = read_json(&spec)?;
    let ledger = OfficeLedger::open(&PathBuf::from(
        ledger.ok_or("provision-batch requires --ledger <file>")?,
    ))?;
    let csv_path = PathBuf::from(csv.ok_or("provision-batch requires --csv <file>")?);
    let csv_text =
        std::fs::read_to_string(&csv_path).map_err(|e| format!("{}: {e}", csv_path.display()))?;
    let out_root = PathBuf::from(out_root.ok_or("provision-batch requires --out-root <dir>")?);
    std::fs::create_dir_all(&out_root)?;
    eprintln!("{DEVICE_CA_CUSTODY_WARNING}");
    if mode == "injected" {
        eprintln!("{INJECTED_KEY_WARNING}");
    }
    let mut report = String::new();
    let mut ok = 0u32;
    let mut failed = 0u32;
    for (line_no, line) in csv_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split(',').map(str::trim).collect();
        if columns
            .first()
            .is_some_and(|first| first.eq_ignore_ascii_case("node"))
        {
            continue;
        }
        match batch_row(&ledger, &ca_key, &spec_json, &out_root, &mode, &columns) {
            Ok((node, serial, out_dir, kid, digest)) => {
                ok += 1;
                report.push_str(&format!(
                    "{{\"node_id\":\"{node:016x}\",\"serial\":{serial},\"out_dir\":\"{}\",\"kid\":\"{}\",\"devcert_sha256\":\"{}\",\"status\":\"ok\"}}\n",
                    routeloom_json::escape_string(&out_dir.to_string_lossy()),
                    hex_encode(&kid),
                    hex_encode(&digest)
                ));
            }
            Err(error) => {
                failed += 1;
                report.push_str(&format!(
                    "{{\"line\":{},\"status\":\"failed\",\"error\":\"{}\"}}\n",
                    line_no + 1,
                    routeloom_json::escape_string(&error)
                ));
                eprintln!("row {}: {error}", line_no + 1);
            }
        }
    }
    let report_path = out_root.join("batch-report.jsonl");
    std::fs::write(&report_path, report.as_bytes())?;
    eprintln!(
        "provision-batch: {ok} ok, {failed} failed ({})",
        report_path.display()
    );
    if failed > 0 {
        return Err(format!("provision-batch: {failed} row(s) failed").into());
    }
    Ok(())
}

/// One issued batch row: node, serial, out dir, kid, DevCert digest.
type BatchRowOutput = (u64, u32, PathBuf, [u8; 32], [u8; 32]);

fn batch_row(
    ledger: &OfficeLedger,
    ca_key: &Path,
    spec_json: &Json,
    out_root: &Path,
    mode: &str,
    columns: &[&str],
) -> Result<BatchRowOutput, String> {
    let fail = |why: &str| -> Result<BatchRowOutput, String> { Err(why.to_string()) };
    let node_text = columns.first().copied().unwrap_or("");
    let node = node_id(node_text).map_err(|e| e.to_string())?;
    let serial: u32 = columns
        .get(1)
        .and_then(|text| text.parse().ok())
        .ok_or("serial must be a u32")
        .map_err(|e: &str| e.to_string())?;
    let (challenge, pop, work_id) = if mode == "devcert" {
        if columns.len() < 4 || columns.len() > 5 {
            return fail("devcert rows are node,serial,challenge_hex,pop_hex[,work_id]");
        }
        let challenge: [u8; 32] = hex_decode_exact(columns[2], 32)
            .ok_or("challenge_hex must be 64 hex")
            .map_err(|e: &str| e.to_string())?
            .try_into()
            .expect("32 bytes");
        if columns[3].len() % 2 != 0
            || columns[3].len() / 2 == 0
            || columns[3].len() / 2 > POP_OBJECT_SIZE
            || !columns[3].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return fail("pop_hex must be even-length hex within the PoP bound");
        }
        let pop = hex_decode_exact(columns[3], columns[3].len() / 2).expect("hex checked");
        let work_id = columns.get(4).map(|text| text.to_string());
        (Some(challenge), Some(pop), work_id)
    } else {
        if columns.len() < 2 || columns.len() > 3 {
            return fail("injected rows are node,serial[,work_id]");
        }
        (None, None, columns.get(2).map(|text| text.to_string()))
    };
    if let Some(work_id) = &work_id {
        if work_id.is_empty() || work_id.len() > 256 {
            return fail("work_id must be 1..=256 bytes");
        }
    }
    let (profile, plan) = identity_spec(spec_json, node, serial).map_err(|e| e.to_string())?;
    let signer = FileDeviceCaSigner::load(ca_key).map_err(|e| e.to_string())?;
    let out_dir = out_root.join(format!("{node:016x}"));
    let inputs = IssuanceInputs {
        ledger: ledger.clone(),
        work_id: work_id.unwrap_or_else(|| default_work_id(&out_dir)),
        out_dir,
        node,
        serial,
        device_ca_id: signer.device_ca_id(),
        plan,
        profile,
        signer,
    };
    let output = if mode == "devcert" {
        run_provision_devcert(
            &inputs,
            &challenge.expect("devcert"),
            &pop.expect("devcert"),
        )
    } else {
        run_provision_identity(&inputs)
    }
    .map_err(|e| e.to_string())?;
    let claims = cert_decode(&output.devcert).map_err(|e| e.to_string())?;
    Ok((
        node,
        serial,
        inputs.out_dir.clone(),
        credential_kid(&claims.pubkey),
        routeloom_provision::sha256::sha256(&output.devcert),
    ))
}

// --- shared option parsing ------------------------------------------------------

struct OfficeOptions {
    ca_key: PathBuf,
    out_dir: PathBuf,
    node: u64,
    profile: DevCertProfile,
    plan: IdentityPlan,
    ledger: Option<PathBuf>,
    work_id: Option<String>,
    extra: Vec<(String, String)>,
}

impl OfficeOptions {
    fn parse(verb: &str, args: &[String], extra_flags: &[&str]) -> Result<Self, DynError> {
        let mut ca_key: Option<String> = None;
        let mut spec: Option<String> = None;
        let mut node: Option<String> = None;
        let mut serial: Option<String> = None;
        let mut out_dir: Option<String> = None;
        let mut ledger: Option<String> = None;
        let mut work_id: Option<String> = None;
        let mut extra = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--ca-key" => ca_key = Some(opt_value(&mut args, "--ca-key")?),
                "--spec" => spec = Some(opt_value(&mut args, "--spec")?),
                "--node" => node = Some(opt_value(&mut args, "--node")?),
                "--serial" => serial = Some(opt_value(&mut args, "--serial")?),
                "--out-dir" => out_dir = Some(opt_value(&mut args, "--out-dir")?),
                "--ledger" => ledger = Some(opt_value(&mut args, "--ledger")?),
                "--work-id" => work_id = Some(opt_value(&mut args, "--work-id")?),
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
        let out_dir =
            PathBuf::from(out_dir.ok_or_else(|| format!("{verb} requires --out-dir <dir>"))?);
        if let Some(work_id) = &work_id {
            if work_id.is_empty() || work_id.len() > 256 {
                return Err("--work-id must be 1..=256 bytes".into());
            }
        }
        Ok(Self {
            ca_key: PathBuf::from(
                ca_key.ok_or_else(|| format!("{verb} requires --ca-key <file>"))?,
            ),
            out_dir,
            node,
            profile,
            plan,
            ledger: ledger.map(PathBuf::from),
            work_id,
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
    use std::io::Read;
    let limit = max
        .checked_mul(2)
        .and_then(|n| n.checked_add(3))
        .ok_or("object limit overflow")?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .take(limit as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() == limit {
        return Err(format!("{}: larger than {max} bytes", path.display()).into());
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        let text = text.trim();
        if !text.is_empty() && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            if text.len() / 2 > max {
                return Err(format!("{}: larger than {max} bytes", path.display()).into());
            }
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

    fn office_setup(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let dir = scratch(tag);
        let key = dir.join("devca.key");
        FileDeviceCaSigner::from_secret(0x0DCA_0000_0000_0001, &[0x51; 32])
            .unwrap()
            .save(&key)
            .unwrap();
        let spec = dir.join("spec.json");
        std::fs::write(&spec, spec_text()).unwrap();
        (dir, key, spec)
    }

    fn identity_args(key: &Path, spec: &Path, node: &str, serial: &str, out: &Path) -> Vec<String> {
        args(&[
            "--ca-key",
            key.to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
            "--node",
            node,
            "--serial",
            serial,
            "--out-dir",
            out.to_str().unwrap(),
        ])
    }

    #[test]
    fn read_object_rejects_hex_over_limit() {
        let dir = scratch("object-bound");
        let path = dir.join("pop.hex");
        std::fs::write(&path, b"0001020304").unwrap();
        assert!(read_object(&path, 4).is_err());
        std::fs::remove_dir_all(dir).unwrap();
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
        // Re-running the same work resumes to the identical output.
        let before: Vec<(String, Vec<u8>)> = [
            "devcert.cwt",
            "identity.rli1",
            "inventory.json",
            "rlident_i0.bin",
            "rlident_i1.bin",
            "rlsec-nvs.csv",
            "rlsec-set.json",
        ]
        .iter()
        .map(|name| (name.to_string(), std::fs::read(out.join(name)).unwrap()))
        .collect();
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
        for (name, bytes) in &before {
            assert_eq!(&std::fs::read(out.join(name)).unwrap(), bytes, "{name}");
        }

        // Device-generated key: PoP (hex file) → DevCert + bundle. A
        // distinct ledger slot (the injected flow above owns 1234/90211).
        let challenge = [0x5A_u8; 32];
        let (device_secret, _) = test_keypair(0x54);
        let pop = pop_sign(
            &device_secret,
            0x00A1_0000_0000_1235,
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
            "90212",
            "--pop",
            pop_path.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
        ];
        // Wrong challenge or wrong node: no DevCert.
        let bad_challenge = "5b".repeat(32);
        let mut wrong = base.to_vec();
        wrong.extend(["--node", "00a1000000001235", "--challenge", &bad_challenge]);
        assert!(provision_devcert_command(&args(&wrong)).is_err());
        let mut wrong = base.to_vec();
        let good_challenge = "5a".repeat(32);
        wrong.extend(["--node", "00a1000000001236", "--challenge", &good_challenge]);
        assert!(provision_devcert_command(&args(&wrong)).is_err());
        assert!(!out.join("devcert.cwt").exists());
        let mut good = base.to_vec();
        good.extend(["--node", "00a1000000001235", "--challenge", &good_challenge]);
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

    #[test]
    fn same_slot_into_another_directory_is_a_duplicate() {
        // P1-2 repro: the same (Device CA, NodeId, serial) issued twice
        // with a fresh key each time mints two competing identities. The
        // office ledger reserves the slot, so the second work refuses.
        let (dir, key, spec) = office_setup("ledger-duplicate");
        let first = dir.join("first");
        let second = dir.join("second");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &first,
        ))
        .unwrap();
        let err = provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &second,
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("already reserved")
                || err.to_string().contains("already issued"),
            "unexpected error: {err}"
        );
        assert!(!second.exists(), "a refused duplicate must publish nothing");
    }

    #[test]
    fn same_node_with_another_serial_is_a_duplicate() {
        // NodeId uniqueness is organization-wide: the same node with a
        // different serial is still a duplicate issuance.
        let (dir, key, spec) = office_setup("ledger-node-clash");
        let first = dir.join("first");
        let second = dir.join("second");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &first,
        ))
        .unwrap();
        assert!(provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90212",
            &second
        ))
        .is_err());
        assert!(!second.exists());
    }

    #[test]
    fn blocked_output_publishes_nothing_and_resumes() {
        // P2-4 repro: a blocked output used to fail partway, leaving
        // devcert.cwt + inventory.json behind while the private files
        // were missing. Issuance now stages to a temp directory and
        // publishes atomically: a blocked output publishes nothing.
        let (dir, key, spec) = office_setup("ledger-blocked");
        let out = dir.join("out");
        std::fs::create_dir_all(out.join("identity.rli1")).unwrap();
        assert!(provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out
        ))
        .is_err());
        assert!(
            !out.join("devcert.cwt").exists(),
            "no partial issuance may be visible"
        );
        assert!(!out.join("inventory.json").exists());
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        assert_eq!(ledger.entries().unwrap()[0].kid, None);
        assert!(!staging_key_file(&staging_dir(&out, &default_work_id(&out))).exists());
        // Clearing the blockage resumes the same work to completion.
        std::fs::remove_dir_all(out.join("identity.rli1")).unwrap();
        std::fs::remove_dir(&out).unwrap();
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .unwrap();
        for name in [
            "devcert.cwt",
            "inventory.json",
            "identity.rli1",
            "rlident_i0.bin",
            "rlident_i1.bin",
            "rlsec-nvs.csv",
            "rlsec-set.json",
        ] {
            assert!(out.join(name).is_file(), "missing {name} after resume");
        }
    }

    #[test]
    fn rerunning_the_same_work_is_idempotent() {
        // P2-4: re-running the same work (same out directory) resumes to
        // the same published output instead of erroring or minting a new
        // key — a crashed run and a re-run converge.
        let (dir, key, spec) = office_setup("ledger-idempotent");
        let out = dir.join("out");
        let argv = identity_args(&key, &spec, "00a1000000001234", "90211", &out);
        provision_identity_command(&argv).unwrap();
        let before: Vec<(String, Vec<u8>)> = std::fs::read_dir(&out)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(&path).unwrap())
            })
            .collect();
        provision_identity_command(&argv).unwrap();
        for (name, bytes) in &before {
            assert_eq!(
                &std::fs::read(out.join(name)).unwrap(),
                bytes,
                "{name} changed"
            );
        }
    }

    #[test]
    fn equivalent_output_spelling_resumes_the_same_work() {
        let (dir, key, spec) = office_setup("ledger-path-spelling");
        let out = dir.join("out");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .unwrap();
        let before = std::fs::read(out.join("devcert.cwt")).unwrap();
        let alias = dir.join(".").join("out");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &alias,
        ))
        .unwrap();
        assert_eq!(std::fs::read(out.join("devcert.cwt")).unwrap(), before);
    }

    #[test]
    fn published_output_with_corrupt_artifact_is_not_adopted() {
        let (dir, key, spec) = office_setup("ledger-corrupt-published");
        let out = dir.join("out");
        let argv = identity_args(&key, &spec, "00a1000000001234", "90211", &out);
        provision_identity_command(&argv).unwrap();
        for name in ["rlident_i0.bin", "rlsec-nvs.csv", "inventory.json"] {
            let path = out.join(name);
            let original = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"corrupt").unwrap();
            assert!(provision_identity_command(&argv).is_err(), "{name}");
            std::fs::write(&path, original).unwrap();
        }
        provision_identity_command(&argv).unwrap();
    }

    #[test]
    fn published_devcert_must_have_a_valid_ca_signature() {
        let (dir, key, spec) = office_setup("ledger-cert-signature");
        let out = dir.join("out");
        let argv = identity_args(&key, &spec, "00a1000000001234", "90211", &out);
        let opts = OfficeOptions::parse("provision-devcert", &argv, &[]).unwrap();
        let inputs = IssuanceInputs::from_options(&opts).unwrap();
        let challenge = [0x5a; 32];
        let (secret, _) = test_keypair(0x54);
        let pop = pop_sign(&secret, inputs.node, KeyLocation::NvsPlaintext, &challenge).unwrap();
        run_provision_devcert(&inputs, &challenge, &pop).unwrap();

        let mut cert = std::fs::read(out.join("devcert.cwt")).unwrap();
        *cert.last_mut().unwrap() ^= 1;
        std::fs::write(out.join("devcert.cwt"), &cert).unwrap();
        std::fs::write(
            out.join("inventory.json"),
            inventory_file_json(&cert, OFFICE_STATUS_ISSUED).unwrap(),
        )
        .unwrap();
        std::fs::write(
            out.join("identity-bundle.json"),
            identity_bundle_json(&inputs.plan, &cert).unwrap(),
        )
        .unwrap();
        assert!(!directory_matches(&out, &DEVCERT_FILES, &inputs).unwrap());
    }

    #[test]
    fn another_device_never_overwrites_an_output() {
        // A different (node, serial) into an occupied directory still
        // refuses: idempotence never overwrites another device's output.
        let (dir, key, spec) = office_setup("ledger-no-overwrite");
        let out = dir.join("out");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .unwrap();
        let devcert_before = std::fs::read(out.join("devcert.cwt")).unwrap();
        assert!(provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001235",
            "90212",
            &out
        ))
        .is_err());
        assert_eq!(
            std::fs::read(out.join("devcert.cwt")).unwrap(),
            devcert_before
        );
    }

    #[test]
    fn crashed_run_resumes_its_staged_key() {
        // A crash between keygen and publish leaves staging behind;
        // the re-run reuses the staged key instead of minting a second
        // key for the same slot.
        let (dir, key, spec) = office_setup("ledger-resume-key");
        let out = dir.join("out");
        let ledger_path = dir.join("office-ledger.jsonl");
        let ledger = OfficeLedger::open(&ledger_path).unwrap();
        let node = 0x00A1_0000_0000_1234;
        let work = default_work_id(&out);
        ledger
            .reserve(
                IssueSlot {
                    device_ca_id: 0x0DCA_0000_0000_0001,
                    node_id: node,
                    serial: 90211,
                },
                None,
                &work,
                &out.to_string_lossy(),
            )
            .unwrap();
        // The crashed run's staging: RLI1 present, the rest missing.
        let signer = FileDeviceCaSigner::load(&key).unwrap();
        let (secret, _) = generate_keypair().unwrap();
        let challenge = pop_challenge().unwrap();
        let pop = pop_sign(&secret, node, KeyLocation::NvsPlaintext, &challenge).unwrap();
        let verified = pop_verify(&pop, node, &challenge).unwrap();
        let (profile, plan) = identity_spec(&read_json(&spec).unwrap(), node, 90211).unwrap();
        let devcert = devcert_issue(&signer, &verified, &profile).unwrap();
        let record = identity_build_injected(&plan, &secret, &devcert).unwrap();
        let staging = staging_dir(&out, &work);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(
            staging.join("identity.rli1"),
            identity_record_encode(&record, IDENTITY_SEAL_COMMITTED).unwrap(),
        )
        .unwrap();
        let staged_kid = record.kid;
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .unwrap();
        // Published with the staged key — not a fresh one.
        let published = std::fs::read(out.join("devcert.cwt")).unwrap();
        let claims = cert_decode(&published).unwrap();
        assert_eq!(credential_kid(&claims.pubkey), staged_kid);
        assert!(!staging.exists(), "staging publishes away");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_staging_without_a_recoverable_key_cannot_reissue() {
        let (dir, key, spec) = office_setup("ledger-uncertain-key");
        let out = dir.join("out");
        let work = default_work_id(&out);
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        ledger
            .reserve(
                IssueSlot {
                    device_ca_id: 0x0DCA_0000_0000_0001,
                    node_id: 0x00A1_0000_0000_1234,
                    serial: 90211,
                },
                None,
                &work,
                &out.to_string_lossy(),
            )
            .unwrap();
        let staging = staging_dir(&out, &work);
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("devcert.cwt"), b"signed but key lost").unwrap();
        assert!(provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .is_err());
        assert!(!out.exists());
    }

    #[test]
    fn signed_staging_reuses_its_durable_key() {
        let (dir, key, spec) = office_setup("ledger-durable-key");
        let out = dir.join("out");
        let work = default_work_id(&out);
        let ledger = OfficeLedger::open(&dir.join("office-ledger.jsonl")).unwrap();
        ledger
            .reserve(
                IssueSlot {
                    device_ca_id: 0x0DCA_0000_0000_0001,
                    node_id: 0x00A1_0000_0000_1234,
                    serial: 90211,
                },
                None,
                &work,
                &out.to_string_lossy(),
            )
            .unwrap();
        let staging = staging_dir(&out, &work);
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("devcert.cwt"), b"prior signed attempt").unwrap();
        let escrow = PathBuf::from(format!("{}.key", staging.display()));
        let (secret, pubkey) = test_keypair(0x54);
        write_private_file(&escrow, &secret).unwrap();
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .unwrap();
        let claims = cert_decode(&std::fs::read(out.join("devcert.cwt")).unwrap()).unwrap();
        assert_eq!(claims.pubkey, pubkey);
        assert!(!escrow.exists());
    }

    #[test]
    fn changed_devcert_cannot_publish_after_prior_issue() {
        let (dir, key, spec) = office_setup("ledger-no-cert-swap");
        let out = dir.join("out");
        let argv = identity_args(&key, &spec, "00a1000000001234", "90211", &out);
        let opts = OfficeOptions::parse("provision-devcert", &argv, &[]).unwrap();
        let inputs = IssuanceInputs::from_options(&opts).unwrap();
        let challenge = [0x5a; 32];
        let (secret, _) = test_keypair(0x54);
        let pop = pop_sign(&secret, inputs.node, KeyLocation::NvsPlaintext, &challenge).unwrap();
        run_provision_devcert(&inputs, &challenge, &pop).unwrap();
        std::fs::remove_dir_all(&out).unwrap();
        std::fs::write(&spec, spec_text().replace("\"model\": 17", "\"model\": 18")).unwrap();
        let changed = OfficeOptions::parse("provision-devcert", &argv, &[]).unwrap();
        let changed_inputs = IssuanceInputs::from_options(&changed).unwrap();
        assert!(run_provision_devcert(&changed_inputs, &challenge, &pop).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn deleting_a_published_output_burns_the_slot() {
        // The published directory is the only copy of an injected key.
        // Deleting it cannot mint a replacement: the slot stays issued,
        // and the re-run refuses before minting (nothing is published).
        let (dir, key, spec) = office_setup("ledger-burned");
        let out = dir.join("out");
        let argv = identity_args(&key, &spec, "00a1000000001234", "90211", &out);
        provision_identity_command(&argv).unwrap();
        std::fs::remove_dir_all(&out).unwrap();
        let err = provision_identity_command(&argv).unwrap_err();
        assert!(
            err.to_string().contains("already issued"),
            "unexpected error: {err}"
        );
        assert!(!out.exists(), "a refused re-mint must publish nothing");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ledger_status_release_and_import() {
        let (dir, key, spec) = office_setup("ledger-ops");
        let ledger_path = dir.join("office-ledger.jsonl");
        let first = dir.join("first");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &first,
        ))
        .unwrap();
        let ledger = OfficeLedger::open(&ledger_path).unwrap();
        let status = routeloom_json::parse(&ledger_status_json(&ledger).unwrap()).unwrap();
        let entries = status.get("entries").and_then(|v| v.as_array()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].get("status").and_then(|v| v.as_str()),
            Some("issued")
        );
        assert_eq!(
            entries[0].get("node_id").and_then(|v| v.as_str()),
            Some("00a1000000001234")
        );
        // An issued slot is never released.
        assert!(provision_ledger_release_command(&args(&[
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--node",
            "00a1000000001234",
            "--serial",
            "90211",
            "--work-id",
            &default_work_id(&first),
        ]))
        .is_err());
        // A reserved-but-abandoned slot releases, freeing the slot.
        let second = dir.join("second");
        let work = default_work_id(&second);
        ledger
            .reserve(
                IssueSlot {
                    device_ca_id: 0x0DCA_0000_0000_0001,
                    node_id: 0x00A1_0000_0000_1235,
                    serial: 90212,
                },
                None,
                &work,
                &second.to_string_lossy(),
            )
            .unwrap();
        provision_ledger_release_command(&args(&[
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--node",
            "00a1000000001235",
            "--serial",
            "90212",
            "--work-id",
            &work,
        ]))
        .unwrap();
        assert_eq!(ledger.entries().unwrap().len(), 1);
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001235",
            "90212",
            &second,
        ))
        .unwrap();
        // A pre-ledger output imports (and re-imports idempotently).
        std::fs::remove_file(&ledger_path).unwrap();
        let import = args(&[
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--out-dir",
            first.to_str().unwrap(),
        ]);
        provision_ledger_import_command(&import).unwrap();
        provision_ledger_import_command(&import).unwrap();
        let entries = ledger.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].node_id, 0x00A1_0000_0000_1234);
        // ... and its slot refuses a duplicate afterwards.
        assert!(provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &dir.join("elsewhere"),
        ))
        .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn confirm_written_matches_the_device_receipt() {
        let (dir, key, spec) = office_setup("ledger-confirm");
        let ledger_path = dir.join("office-ledger.jsonl");
        let out = dir.join("out");
        let mut argv = identity_args(&key, &spec, "00a1000000001234", "90211", &out);
        argv.extend(args(&["--ledger", ledger_path.to_str().unwrap()]));
        provision_identity_command(&argv).unwrap();
        let devcert = std::fs::read(out.join("devcert.cwt")).unwrap();
        let digest = hex_encode(&routeloom_provision::sha256::sha256(&devcert));
        // A wrong receipt refuses — it is a mixup, never a typo.
        let mut bad = digest.clone();
        bad.replace_range(0..1, if bad.starts_with('0') { "1" } else { "0" });
        assert!(provision_confirm_written_command(&args(&[
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--node",
            "00a1000000001234",
            "--devcert-sha256",
            &bad,
        ]))
        .is_err());
        // The right receipt confirms and flips the inventory state.
        provision_confirm_written_command(&args(&[
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--node",
            "00a1000000001234",
            "--devcert-sha256",
            &digest,
            "--out-dir",
            out.to_str().unwrap(),
        ]))
        .unwrap();
        let ledger = OfficeLedger::open(&ledger_path).unwrap();
        assert_eq!(
            ledger.entries().unwrap()[0].status,
            crate::office_ledger::LedgerStatus::Written
        );
        let inventory =
            routeloom_json::parse(&std::fs::read_to_string(out.join("inventory.json")).unwrap())
                .unwrap();
        assert_eq!(
            inventory.get("office_status").and_then(|v| v.as_str()),
            Some("written")
        );
        // Confirming twice is fine.
        provision_confirm_written_command(&args(&[
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--node",
            "00a1000000001234",
            "--devcert-sha256",
            &digest,
        ]))
        .unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expect_sheet_matches_the_console_receipt() {
        let (dir, key, spec) = office_setup("ledger-expect");
        let out = dir.join("out");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .unwrap();
        let (status, lock_kid, office_status) = expect_sheet(&out, None).unwrap();
        let devcert = std::fs::read(out.join("devcert.cwt")).unwrap();
        let claims = cert_decode(&devcert).unwrap();
        let kid = hex_encode(&credential_kid(&claims.pubkey));
        assert_eq!(
            status,
            format!(
                "OK identity=sealed pending=0 locked=0 node=00a1000000001234 kid={kid} serial=90211 devcert_sha256={}",
                hex_encode(&routeloom_provision::sha256::sha256(&devcert))
            )
        );
        assert_eq!(lock_kid, kid);
        assert_eq!(office_status, "issued");
        assert!(provision_expect_command(&args(&["--out-dir", out.to_str().unwrap()])).is_ok());
        // A mixed directory (inventory from another device) refuses.
        let other = dir.join("other");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001235",
            "90212",
            &other,
        ))
        .unwrap();
        std::fs::copy(other.join("inventory.json"), out.join("inventory.json")).unwrap();
        assert!(expect_sheet(&out, None).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expect_sheet_with_fw_matches_the_versioned_receipt() {
        let (dir, key, spec) = office_setup("ledger-expect-fw");
        let out = dir.join("out");
        provision_identity_command(&identity_args(
            &key,
            &spec,
            "00a1000000001234",
            "90211",
            &out,
        ))
        .unwrap();
        let (status, _, _) = expect_sheet(&out, Some("rl-9.9.9-maintenance")).unwrap();
        assert!(
            status.ends_with(" fw=rl-9.9.9-maintenance"),
            "unexpected: {status}"
        );
        // The office rule mirrors the console: blank, spaced or over-long
        // versions refuse instead of printing a line that never matches.
        assert!(expect_sheet(&out, Some("")).is_err());
        assert!(expect_sheet(&out, Some("rl 9")).is_err());
        assert!(expect_sheet(&out, Some(&"v".repeat(33))).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn batch_issues_many_and_reports_per_row() {
        let (dir, key, spec) = office_setup("ledger-batch");
        let ledger_path = dir.join("office-ledger.jsonl");
        let csv = dir.join("batch.csv");
        std::fs::write(
            &csv,
            "# factory lot 7\nnode,serial\n00a1000000001234,90211\n00a1000000001235,90212\nnot-a-node,90213\n",
        )
        .unwrap();
        let root = dir.join("lot");
        let batch = args(&[
            "--ca-key",
            key.to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--csv",
            csv.to_str().unwrap(),
            "--out-root",
            root.to_str().unwrap(),
            "--mode",
            "injected",
        ]);
        // One bad row fails the command but never stops the batch.
        assert!(provision_batch_command(&batch).is_err());
        assert!(root.join("00a1000000001234").join("devcert.cwt").is_file());
        assert!(root.join("00a1000000001235").join("devcert.cwt").is_file());
        let report = std::fs::read_to_string(root.join("batch-report.jsonl")).unwrap();
        assert_eq!(report.lines().count(), 3);
        assert_eq!(report.matches("\"status\":\"ok\"").count(), 2);
        assert_eq!(report.matches("\"status\":\"failed\"").count(), 1);
        // Fixing the CSV resumes the batch to green.
        std::fs::write(&csv, "00a1000000001234,90211\n00a1000000001235,90212\n").unwrap();
        provision_batch_command(&batch).unwrap();
        let report = std::fs::read_to_string(root.join("batch-report.jsonl")).unwrap();
        assert_eq!(report.matches("\"status\":\"ok\"").count(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn batch_devcert_mode_consumes_collected_pops() {
        let (dir, key, spec) = office_setup("ledger-batch-devcert");
        let ledger_path = dir.join("office-ledger.jsonl");
        let challenge = [0x5A_u8; 32];
        let (device_secret, _) = test_keypair(0x54);
        let pop = pop_sign(
            &device_secret,
            0x00A1_0000_0000_1234,
            KeyLocation::NvsPlaintext,
            &challenge,
        )
        .unwrap();
        let csv = dir.join("batch.csv");
        std::fs::write(
            &csv,
            format!(
                "00a1000000001234,90211,{},{}",
                hex_encode(&challenge),
                hex_encode(&pop)
            ),
        )
        .unwrap();
        let root = dir.join("lot");
        provision_batch_command(&args(&[
            "--ca-key",
            key.to_str().unwrap(),
            "--spec",
            spec.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--csv",
            csv.to_str().unwrap(),
            "--out-root",
            root.to_str().unwrap(),
        ]))
        .unwrap();
        let out = root.join("00a1000000001234");
        assert!(out.join("devcert.cwt").is_file());
        assert!(out.join("identity-bundle.json").is_file());
        assert!(!out.join("identity.rli1").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
