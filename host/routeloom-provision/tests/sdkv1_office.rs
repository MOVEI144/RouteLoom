//! Office tooling (docs/design/sdk-v1/07 §6, 08 P7-1, acceptance V1-H09):
//! proof of possession → DevCert issue through the `DeviceCaSigner` seam →
//! RLI1 → `rlsec` NVS set, then back through the P1 codecs and the chain
//! checks a device and a Site Authority apply.
//!
//! The golden case uses the `protocol/sdkv1-golden/` fixture keys (Device
//! CA seed 0x51, device 0x54, Site CA 0x52, verifier 0x55) and requires the
//! issued DevCert and the injected-key RLI1 to equal the independent
//! generator's bytes exactly — the office path produces nothing the shared
//! vectors would not.

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_provision::credential::{credential_kid, KeyLocation};
use routeloom_provision::nvs::NvsValue;
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType, SITE_USAGE_AUTHORITY};
use routeloom_provision::sdkv1::devca::{
    devcert_issue, devcert_verify, DevCertProfile, DeviceCaSigner, FileDeviceCaSigner,
};
use routeloom_provision::sdkv1::identity::{
    identity_record_decode, identity_record_encode, identity_verify_site_cert, AnchorKind,
    AnchorStatus, IdentityAnchor, FLAG_CONSOLE_LOCKED, FLAG_STRICT_ASSIGNMENT,
    IDENTITY_SEAL_COMMITTED,
};
use routeloom_provision::sdkv1::office::{
    identity_build_injected, identity_bundle_json, inventory_file_json, inventory_json,
    IdentityPlan, INVENTORY_FORMAT, OFFICE_STATUS_ISSUED,
};
use routeloom_provision::sdkv1::pop::{pop_challenge, pop_sign, pop_verify};
use routeloom_provision::sdkv1::rlsec::{rlsec_identity_readback, rlsec_identity_set};
use routeloom_provision::sdkv1::siteca::{
    sitecert_issue, sitecert_verify, FileSiteCaSigner, SiteCaSigner, SiteCertProfile,
    SITE_CA_KEY_FORMAT,
};
use routeloom_provision::signer::{generate_keypair, test_keypair, FileRootSigner};
use routeloom_provision::Code;

const DEVICE_CA_ID: u64 = 0x0DCA_0000_0000_0001;
const SITE_CA_ID: u64 = 0x05CA_0000_0000_0001;
const SITE_CA_DISABLED_ID: u64 = 0x05CA_0000_0000_0002;
const VERIFIER_ID: u64 = 0x0A55_0000_0000_0001;
const SITE_ID: u64 = 0x5173_0000_0000_0042;
const NODE: u64 = 0x00A1_0000_0000_1234;

fn golden(name: &str) -> routeloom_json::Json {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/sdkv1-golden/valid")
        .join(name);
    routeloom_json::parse(&fs::read_to_string(&path).unwrap()).unwrap()
}

fn golden_hex(doc: &routeloom_json::Json, key: &str) -> Vec<u8> {
    let text = doc.get(key).and_then(|v| v.as_str()).unwrap();
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn anchor(id: u64, kind: AnchorKind, status: AnchorStatus, seed: u8) -> IdentityAnchor {
    IdentityAnchor {
        anchor_id: id,
        kind,
        status,
        pubkey: test_keypair(seed).1,
    }
}

fn golden_plan() -> IdentityPlan {
    IdentityPlan {
        node_id: NODE,
        flags: FLAG_CONSOLE_LOCKED | FLAG_STRICT_ASSIGNMENT,
        anchors: vec![
            anchor(SITE_CA_ID, AnchorKind::SiteCa, AnchorStatus::Active, 0x52),
            anchor(
                SITE_CA_DISABLED_ID,
                AnchorKind::SiteCa,
                AnchorStatus::Disabled,
                0x57,
            ),
            anchor(
                VERIFIER_ID,
                AnchorKind::AssignmentVerifier,
                AnchorStatus::Active,
                0x55,
            ),
        ],
    }
}

fn golden_profile() -> DevCertProfile {
    DevCertProfile {
        model: 17,
        hw_rev: 2,
        serial: 90211,
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rl-office-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn pop_devcert_identity_and_nvs_reproduce_golden() {
    let device_ca = FileDeviceCaSigner::from_secret(DEVICE_CA_ID, &[0x51; 32]).unwrap();
    let (device_secret, device_pub) = test_keypair(0x54);
    let challenge = pop_challenge().unwrap();
    let pop = pop_sign(&device_secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap();
    let key = pop_verify(&pop, NODE, &challenge).unwrap();
    assert_eq!(key.pubkey(), device_pub);

    let devcert = devcert_issue(&device_ca, &key, &golden_profile()).unwrap();
    assert_eq!(
        devcert,
        golden_hex(&golden("cert_devcert.json"), "cert_hex")
    );

    let rli1 = golden("rli1_strict_three_anchors.json");
    assert_eq!(devcert, golden_hex(&rli1, "devcert_hex"));
    let record = identity_build_injected(&golden_plan(), &device_secret, &devcert).unwrap();
    let encoded = identity_record_encode(&record, IDENTITY_SEAL_COMMITTED).unwrap();
    assert_eq!(encoded, golden_hex(&rli1, "record_hex"));

    // rlsec NVS set: identical committed twin blobs of exactly used_len
    // bytes under rlident/i0,i1; reads back as the same record.
    let set = rlsec_identity_set(&record).unwrap();
    assert_eq!(set.entries.len(), 2);
    for (entry, key) in set.entries.iter().zip(["i0", "i1"]) {
        assert_eq!(entry.namespace, "rlident");
        assert_eq!(entry.key, key);
        assert_eq!(entry.value, NvsValue::Blob(encoded.clone()));
        assert_eq!(entry.slot_bytes(), Some(1024));
    }
    assert_eq!(rlsec_identity_readback(&set).unwrap(), record);
    assert_eq!(
        set.partition_csv(),
        "key,type,encoding,value\nrlident,namespace,,\ni0,file,binary,rlident_i0.bin\ni1,file,binary,rlident_i1.bin\n"
    );
    let descriptor = routeloom_json::parse(&set.descriptor_json()).unwrap();
    assert_eq!(
        descriptor.get("partition").and_then(|v| v.as_str()),
        Some("rlsec")
    );
    let entries = descriptor
        .get("entries")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(golden_hex(&entries[1], "data_hex"), encoded);
}

#[test]
fn issue_parse_verify_chain_with_fresh_keys() {
    // Fresh (random) keys end to end: nothing depends on fixture seeds.
    let device_ca = FileDeviceCaSigner::generate(DEVICE_CA_ID).unwrap();
    let (site_ca_secret, site_ca_pub) = generate_keypair().unwrap();
    let (sak_secret, sak_pub) = generate_keypair().unwrap();
    let (device_secret, device_pub) = generate_keypair().unwrap();
    let challenge = pop_challenge().unwrap();
    let key = pop_verify(
        &pop_sign(&device_secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap(),
        NODE,
        &challenge,
    )
    .unwrap();
    let devcert = devcert_issue(&device_ca, &key, &golden_profile()).unwrap();
    let plan = IdentityPlan {
        node_id: NODE,
        flags: 0,
        anchors: vec![IdentityAnchor {
            anchor_id: SITE_CA_ID,
            kind: AnchorKind::SiteCa,
            status: AnchorStatus::Active,
            pubkey: site_ca_pub,
        }],
    };
    let record = identity_build_injected(&plan, &device_secret, &devcert).unwrap();
    let set = rlsec_identity_set(&record).unwrap();

    // Device boot: the manufactured blob decodes as a committed RLI1.
    let NvsValue::Blob(blob) = &set.entries[0].value else {
        panic!("blob expected");
    };
    let booted = identity_record_decode(blob).unwrap();
    assert_eq!(booted.kid, credential_kid(&device_pub));
    assert_eq!(booted.key_location, KeyLocation::NvsPlaintext);

    // Site Authority (02 §8 VERIFY): DevCert chains to the Device CA only.
    let claims = devcert_verify(&booted.devcert, DEVICE_CA_ID, &device_ca.pubkey()).unwrap();
    assert_eq!(claims.subject, NODE);
    assert_eq!(claims.pubkey, device_pub);
    assert_eq!(claims.serial, 90211);
    let other_ca = FileDeviceCaSigner::generate(DEVICE_CA_ID).unwrap();
    assert_eq!(
        devcert_verify(&booted.devcert, DEVICE_CA_ID, &other_ca.pubkey())
            .unwrap_err()
            .code,
        Code::AuthorizationFailed
    );
    assert_eq!(
        devcert_verify(&booted.devcert, DEVICE_CA_ID + 1, &device_ca.pubkey())
            .unwrap_err()
            .code,
        Code::AuthorizationFailed
    );

    // Device (02 §10.1 m2): a SiteCert from the configured Site CA chains
    // to the RLI1 anchor; one from any other CA does not.
    let site_claims = CertClaims {
        cert_type: CertType::Site,
        issuer: SITE_CA_ID,
        subject: SITE_ID,
        pubkey: sak_pub,
        network_low32: 0x0A1B_2C3D,
        site_epoch: 3,
        usage: SITE_USAGE_AUTHORITY,
        serial: 7,
        ..CertClaims::default()
    };
    let site_ca = FileRootSigner::from_secret(SITE_CA_ID, &site_ca_secret).unwrap();
    let site_cert = cert_issue(&site_claims, &site_ca).unwrap();
    let (decoded, verified) = identity_verify_site_cert(&booted, &site_cert).unwrap();
    assert!(verified);
    assert_eq!(decoded.subject, SITE_ID);
    let rogue = FileRootSigner::from_secret(SITE_CA_ID, &sak_secret).unwrap();
    let rogue_cert = cert_issue(&site_claims, &rogue).unwrap();
    assert!(!identity_verify_site_cert(&booted, &rogue_cert).unwrap().1);
    // Inventory is derived from the DevCert.
    let line = routeloom_json::parse(&inventory_json(&devcert).unwrap()).unwrap();
    assert_eq!(
        line.get("node_id").and_then(|v| v.as_str()),
        Some("00a1000000001234")
    );
    assert_eq!(
        line.get("cert_serial").and_then(|v| v.as_u64()),
        Some(90211)
    );
    assert_eq!(line.get("model").and_then(|v| v.as_u64()), Some(17));
}

#[test]
fn no_devcert_without_proof_of_possession() {
    // The only way to a VerifiedDeviceKey (and so to devcert_issue) is
    // pop_verify; every way a proof can be wrong is refused.
    let (device_secret, _) = test_keypair(0x54);
    let (attacker_secret, _) = test_keypair(0x56);
    let challenge = [0x33_u8; 32];
    let pop = pop_sign(&device_secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap();
    // Replayed against a new challenge.
    assert_eq!(
        pop_verify(&pop, NODE, &[0x34; 32]).unwrap_err().code,
        Code::AuthorizationFailed
    );
    // Presented for another node id.
    assert_eq!(
        pop_verify(&pop, NODE + 1, &challenge).unwrap_err().code,
        Code::AuthorizationFailed
    );
    // An attacker's own valid proof names the attacker's key, never the
    // victim's: the DevCert would bind the attacker key, which is what the
    // office then sees in the inventory, not a certificate for the victim.
    let attacker = pop_verify(
        &pop_sign(
            &attacker_secret,
            NODE,
            KeyLocation::NvsPlaintext,
            &challenge,
        )
        .unwrap(),
        NODE,
        &challenge,
    )
    .unwrap();
    assert_ne!(attacker.pubkey(), test_keypair(0x54).1);
    // Corrupt bytes anywhere in the object are refused.
    for index in [0, 9, 20, 60, 120, 150, 182] {
        let mut bad = pop.clone();
        bad[index] ^= 0x01;
        assert!(pop_verify(&bad, NODE, &challenge).is_err(), "byte {index}");
    }
}

#[test]
fn identity_build_refuses_what_the_device_would_refuse() {
    let device_ca = FileDeviceCaSigner::from_secret(DEVICE_CA_ID, &[0x51; 32]).unwrap();
    let (device_secret, _) = test_keypair(0x54);
    let challenge = [0x44_u8; 32];
    let key = pop_verify(
        &pop_sign(&device_secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap(),
        NODE,
        &challenge,
    )
    .unwrap();
    let devcert = devcert_issue(&device_ca, &key, &golden_profile()).unwrap();
    // DevCert for a different key than the injected secret.
    let (other_secret, _) = test_keypair(0x56);
    assert!(identity_build_injected(&golden_plan(), &other_secret, &devcert).is_err());
    // DevCert for another node.
    let mut plan = golden_plan();
    plan.node_id = NODE + 1;
    assert!(identity_build_injected(&plan, &device_secret, &devcert).is_err());
    // No active Site CA anchor.
    let mut plan = golden_plan();
    plan.flags = 0;
    plan.anchors = vec![anchor(
        SITE_CA_ID,
        AnchorKind::SiteCa,
        AnchorStatus::Disabled,
        0x52,
    )];
    assert!(identity_build_injected(&plan, &device_secret, &devcert).is_err());
    // Strict assignment without a verifier anchor.
    let mut plan = golden_plan();
    plan.anchors.truncate(1);
    assert!(identity_build_injected(&plan, &device_secret, &devcert).is_err());
    // Duplicate anchor ids.
    let mut plan = golden_plan();
    plan.anchors[1].anchor_id = SITE_CA_ID;
    assert!(identity_build_injected(&plan, &device_secret, &devcert).is_err());
    // Unknown flag bits.
    let mut plan = golden_plan();
    plan.flags |= 0x80;
    assert!(identity_build_injected(&plan, &device_secret, &devcert).is_err());
}

#[test]
fn identity_bundle_for_device_generated_keys() {
    let device_ca = FileDeviceCaSigner::from_secret(DEVICE_CA_ID, &[0x51; 32]).unwrap();
    let (device_secret, device_pub) = test_keypair(0x54);
    let challenge = [0x45_u8; 32];
    let key = pop_verify(
        &pop_sign(&device_secret, NODE, KeyLocation::SecureElement, &challenge).unwrap(),
        NODE,
        &challenge,
    )
    .unwrap();
    assert_eq!(key.key_location(), KeyLocation::SecureElement);
    let devcert = devcert_issue(&device_ca, &key, &golden_profile()).unwrap();
    let bundle = identity_bundle_json(&golden_plan(), &devcert).unwrap();
    // No secret anywhere in the bundle.
    assert!(!bundle.contains(&"54".repeat(32)));
    let doc = routeloom_json::parse(&bundle).unwrap();
    assert_eq!(
        doc.get("format").and_then(|v| v.as_str()),
        Some("routeloom-identity-bundle-v1")
    );
    assert_eq!(
        doc.get("node_id").and_then(|v| v.as_str()),
        Some("00a1000000001234")
    );
    assert_eq!(golden_hex(&doc, "pubkey_hex"), device_pub.to_vec());
    assert_eq!(golden_hex(&doc, "devcert_hex"), devcert);
    let anchors = doc.get("anchors").and_then(|v| v.as_array()).unwrap();
    assert_eq!(anchors.len(), 3);
    assert_eq!(
        anchors[2].get("kind").and_then(|v| v.as_str()),
        Some("assignment-verifier")
    );
    // A bundle naming another node than its DevCert is refused.
    let mut plan = golden_plan();
    plan.node_id = NODE + 1;
    assert!(identity_bundle_json(&plan, &devcert).is_err());
}

#[test]
fn sitecert_issue_matches_golden_and_verifies() {
    // The shared vector's SiteCert, re-issued through the Site CA seam.
    let site_ca = FileSiteCaSigner::from_secret(SITE_CA_ID, &[0x52; 32]).unwrap();
    let (_, sak_pub) = test_keypair(0x53);
    let profile = SiteCertProfile {
        network_low32: 0x0A1B_2C3D,
        site_epoch: 3,
        serial: 7,
    };
    let sitecert = sitecert_issue(&site_ca, SITE_ID, &sak_pub, &profile).unwrap();
    assert_eq!(
        sitecert,
        golden_hex(&golden("cert_sitecert.json"), "cert_hex")
    );
    let claims = sitecert_verify(&sitecert, SITE_CA_ID, &site_ca.pubkey()).unwrap();
    assert_eq!(claims.subject, SITE_ID);
    assert_eq!(claims.pubkey, sak_pub);
    assert_eq!(claims.serial, 7);
    // Another CA's id or key does not verify it.
    assert_eq!(
        sitecert_verify(&sitecert, SITE_CA_ID + 1, &site_ca.pubkey())
            .unwrap_err()
            .code,
        Code::AuthorizationFailed
    );
    let other_ca = FileSiteCaSigner::generate(SITE_CA_ID).unwrap();
    assert_eq!(
        sitecert_verify(&sitecert, SITE_CA_ID, &other_ca.pubkey())
            .unwrap_err()
            .code,
        Code::AuthorizationFailed
    );
    // A DevCert is not a SiteCert.
    let device_ca = FileDeviceCaSigner::from_secret(DEVICE_CA_ID, &[0x51; 32]).unwrap();
    let (device_secret, _) = test_keypair(0x54);
    let challenge = [0x46_u8; 32];
    let key = pop_verify(
        &pop_sign(&device_secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap(),
        NODE,
        &challenge,
    )
    .unwrap();
    let devcert = devcert_issue(&device_ca, &key, &golden_profile()).unwrap();
    assert_eq!(
        sitecert_verify(&devcert, SITE_CA_ID, &site_ca.pubkey())
            .unwrap_err()
            .code,
        Code::AuthorizationFailed
    );
    // Unusable inputs are refused, never minted.
    assert!(sitecert_issue(&site_ca, 0, &sak_pub, &profile).is_err());
    assert!(sitecert_issue(&site_ca, SITE_ID, &[0x11; 64], &profile).is_err());
    assert!(sitecert_issue(
        &site_ca,
        SITE_ID,
        &sak_pub,
        &SiteCertProfile {
            network_low32: 0,
            ..profile
        },
    )
    .is_err());
}

#[test]
fn site_ca_key_file_custody() {
    let dir = scratch_dir("siteca");
    let path = dir.join("siteca.key");
    let signer = FileSiteCaSigner::from_secret(SITE_CA_ID, &[0x52; 32]).unwrap();
    signer.save(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let loaded = FileSiteCaSigner::load(&path).unwrap();
    assert_eq!(loaded.site_ca_id(), SITE_CA_ID);
    assert_eq!(loaded.pubkey(), signer.pubkey());
    assert_eq!(loaded.sign(b"x").unwrap(), signer.sign(b"x").unwrap());
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains(&format!("\"format\": \"{SITE_CA_KEY_FORMAT}\"")));
    assert!(text.contains("\"site_ca_id\": \"05ca000000000001\""));
    // Never overwrite.
    assert!(signer.save(&path).is_err());
    // A Device CA document is not a Site CA key and vice versa (no silent
    // cross-use between the authorities).
    let devca_path = dir.join("devca.key");
    FileDeviceCaSigner::from_secret(DEVICE_CA_ID, &[0x51; 32])
        .unwrap()
        .save(&devca_path)
        .unwrap();
    assert_eq!(
        FileSiteCaSigner::load(&devca_path).err().unwrap().code,
        Code::ProtocolError
    );
    assert!(FileDeviceCaSigner::load(&path).is_err());
    // Group/other-readable key files are refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            FileSiteCaSigner::load(&path).err().unwrap().code,
            Code::AuthorizationFailed
        );
    }
    // Invalid ids are refused at construction.
    assert!(FileSiteCaSigner::from_secret(0, &[0x52; 32]).is_err());
    assert!(FileSiteCaSigner::from_secret(u64::MAX, &[0x52; 32]).is_err());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn inventory_file_is_the_formal_record() {
    let device_ca = FileDeviceCaSigner::from_secret(DEVICE_CA_ID, &[0x51; 32]).unwrap();
    let (device_secret, _) = test_keypair(0x54);
    let challenge = [0x47_u8; 32];
    let key = pop_verify(
        &pop_sign(&device_secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap(),
        NODE,
        &challenge,
    )
    .unwrap();
    let devcert = devcert_issue(&device_ca, &key, &golden_profile()).unwrap();
    let file = routeloom_json::parse(&inventory_file_json(&devcert, OFFICE_STATUS_ISSUED).unwrap())
        .unwrap();
    assert_eq!(
        file.get("format").and_then(|v| v.as_str()),
        Some(INVENTORY_FORMAT)
    );
    assert_eq!(
        file.get("office_status").and_then(|v| v.as_str()),
        Some(OFFICE_STATUS_ISSUED)
    );
    assert!(inventory_file_json(&devcert, "bogus").is_err());
    // Same record as the stdout line, derived from the DevCert alone.
    let line = routeloom_json::parse(&inventory_json(&devcert).unwrap()).unwrap();
    for field in [
        "node_id",
        "kid",
        "model",
        "hw_rev",
        "cert_serial",
        "device_ca_id",
    ] {
        assert_eq!(file.get(field), line.get(field), "{field}");
    }
    assert!(inventory_file_json(b"not a certificate", OFFICE_STATUS_ISSUED).is_err());
}

#[test]
fn device_ca_key_file_custody() {
    let dir = scratch_dir("devca");
    let path = dir.join("devca.key");
    let signer = FileDeviceCaSigner::from_secret(DEVICE_CA_ID, &[0x51; 32]).unwrap();
    signer.save(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let loaded = FileDeviceCaSigner::load(&path).unwrap();
    assert_eq!(loaded.device_ca_id(), DEVICE_CA_ID);
    assert_eq!(loaded.pubkey(), signer.pubkey());
    assert_eq!(loaded.sign(b"x").unwrap(), signer.sign(b"x").unwrap());
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"format\": \"routeloom-device-ca-key-v1\""));
    assert!(text.contains("\"device_ca_id\": \"0dca000000000001\""));
    // Never overwrite.
    assert!(signer.save(&path).is_err());
    // A root key document is not a Device CA key (no silent cross-use),
    // and a Device CA document is not a root key.
    let root_path = dir.join("root.key");
    FileRootSigner::from_secret(0x100, &[0x11; 32])
        .unwrap()
        .save(&root_path)
        .unwrap();
    assert_eq!(
        FileDeviceCaSigner::load(&root_path).err().unwrap().code,
        Code::ProtocolError
    );
    assert!(FileRootSigner::load(&path).is_err());
    // Group/other-readable key files are refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            FileDeviceCaSigner::load(&path).err().unwrap().code,
            Code::AuthorizationFailed
        );
    }
    // Invalid ids are refused at construction.
    assert!(FileDeviceCaSigner::from_secret(0, &[0x51; 32]).is_err());
    assert!(FileDeviceCaSigner::from_secret(u64::MAX, &[0x51; 32]).is_err());
    fs::remove_dir_all(&dir).ok();
}
