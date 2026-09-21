//! Regenerates the shared provisioning golden vectors under
//! `protocol/provisioning-golden/`. Run with:
//! `cargo run -p routeloom-provision --example gen_provisioning_golden`
//!
//! Key material is the fixed `test_keypair(seed)` family (the private
//! scalar is the seed byte repeated 32×) — the same fixtures the C++ suite
//! uses — and RFC 6979 deterministic signing, so every byte in this
//! directory is reproducible. TEST MATERIAL ONLY.

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_provision::credential::{
    credential_cose_key_encode, credential_kid, credential_record_encode, grant_fixture,
    CredStatus, DeviceCredential, KeyLocation, CRED_SEAL_COMMITTED,
};
use routeloom_provision::image::{
    image_body_encode, image_encode, image_fingerprint, AnchorStatus, KeyStatus, TrustAnchor,
    TrustImage, TrustKeyRecord, TrustRevocation, TRUST_SEAL_COMMITTED,
};
use routeloom_provision::manifest::{manifest_assemble, manifest_sign, manifest_sign_with_aad};
use routeloom_provision::nvs::{manufacture_nvs_set, NvsValue};
use routeloom_provision::signer::{hex_encode, test_keypair, FileRootSigner, RootSigner};
use routeloom_provision::verify::verify_manifest;

const NETWORK: u64 = 7;
const DEPLOYMENT: u64 = 0xDE9;
const ROOT_ID_A: u64 = 0x100;
const ROOT_ID_B: u64 = 0x200;
const AUTHORITY_ID: u64 = 0xA17;
const NODE_ID: u64 = 0xC3;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/provisioning-golden")
}

fn write(dir: &Path, name: &str, text: &str) {
    fs::write(dir.join(name), text).unwrap_or_else(|e| panic!("write {name}: {e}"));
    println!("wrote {name}");
}

fn root_a() -> FileRootSigner {
    FileRootSigner::from_secret(ROOT_ID_A, &test_keypair(0x11).0).unwrap()
}

fn anchor_a() -> TrustAnchor {
    TrustAnchor {
        root_id: ROOT_ID_A,
        pubkey: test_keypair(0x11).1,
        status: AnchorStatus::Active,
    }
}

fn authority_key(generation: u32, status: KeyStatus) -> TrustKeyRecord {
    TrustKeyRecord {
        authority_id: AUTHORITY_ID,
        generation,
        profile: 1,
        role: 1,
        status,
        scope: 0,
        pubkey: test_keypair(0x33).1,
    }
}

/// Committed epoch-1 image: root A active, authority gen 1 active.
fn image_epoch1() -> TrustImage {
    TrustImage {
        store_epoch: 1,
        min_authority_generation: 1,
        network: NETWORK,
        deployment_id: DEPLOYMENT,
        flags: 0,
        anchors: vec![anchor_a()],
        keys: vec![authority_key(1, KeyStatus::Active)],
        revocations: Vec::new(),
    }
}

/// Epoch-2 candidate: same anchors/keys plus one credential revocation.
fn image_epoch2() -> TrustImage {
    let mut image = image_epoch1();
    image.store_epoch = 2;
    image.revocations.push(TrustRevocation {
        node_id: 0x77,
        kid_fingerprint: credential_kid(&test_keypair(0x66).1),
        revoked_at_epoch: 2,
        kind: 1,
    });
    image
}

fn anchors_json(image: &TrustImage) -> String {
    let mut out = String::new();
    for (i, a) in image.anchors.iter().enumerate() {
        out.push_str(&format!(
            "{}    {{\"root_id\": \"{:016x}\", \"pubkey_hex\": \"{}\", \"status\": \"{}\"}}",
            if i == 0 { "\n" } else { ",\n" },
            a.root_id,
            hex_encode(&a.pubkey),
            match a.status {
                AnchorStatus::Active => "active",
                AnchorStatus::Disabled => "disabled",
            },
        ));
    }
    out
}

fn keys_json(image: &TrustImage) -> String {
    let mut out = String::new();
    for (i, k) in image.keys.iter().enumerate() {
        out.push_str(&format!(
            "{}    {{\"authority_id\": \"{:016x}\", \"generation\": {}, \"profile\": {}, \"role\": {}, \"status\": \"{}\", \"scope\": {}, \"pubkey_hex\": \"{}\"}}",
            if i == 0 { "\n" } else { ",\n" },
            k.authority_id,
            k.generation,
            k.profile,
            k.role,
            match k.status {
                KeyStatus::Staged => "staged",
                KeyStatus::Active => "active",
                KeyStatus::Retired => "retired",
                KeyStatus::Revoked => "revoked",
            },
            k.scope,
            hex_encode(&k.pubkey),
        ));
    }
    out
}

fn revocations_json(image: &TrustImage) -> String {
    let mut out = String::new();
    for (i, r) in image.revocations.iter().enumerate() {
        out.push_str(&format!(
            "{}    {{\"node_id\": \"{:016x}\", \"kid_hex\": \"{}\", \"revoked_at_epoch\": {}, \"kind\": {}}}",
            if i == 0 { "\n" } else { ",\n" },
            r.node_id,
            hex_encode(&r.kid_fingerprint),
            r.revoked_at_epoch,
            r.kind,
        ));
    }
    out
}

/// A golden trust-image document: the spec fields (so the file doubles
/// as a `provision-image --spec` input) plus the encoded RLT1 record,
/// the RTM1 signed content (RLT1 bytes [16, used-4)) and the record
/// fingerprint.
fn image_doc(name: &str, comment: &str, image: &TrustImage) -> String {
    let record = image_encode(image, TRUST_SEAL_COMMITTED).unwrap();
    let content = image_body_encode(image).unwrap();
    format!(
        "{{\n  \"format\": \"routeloom-provisioning-golden-v1\",\n  \"kind\": \"trust-image\",\n  \"name\": \"{name}\",\n  \"comment\": \"{comment}\",\n  \"store_epoch\": {},\n  \"min_authority_generation\": {},\n  \"network\": \"{:016x}\",\n  \"deployment_id\": \"{:016x}\",\n  \"flags\": {},\n  \"anchors\": [{}],\n  \"keys\": [{}],\n  \"revocations\": [{}],\n  \"record_hex\": \"{}\",\n  \"content_hex\": \"{}\",\n  \"fingerprint_hex\": \"{}\"\n}}\n",
        image.store_epoch,
        image.min_authority_generation,
        image.network,
        image.deployment_id,
        image.flags,
        anchors_json(image),
        keys_json(image),
        revocations_json(image),
        hex_encode(&record),
        hex_encode(&content),
        hex_encode(&image_fingerprint(&record).unwrap()),
    )
}

/// A verify-vector document: a committed "current" RLT1 record and an
/// RTM1 object with the device-equivalent verdict the acceptance pipeline
/// must return (`expect` is the Code name — "accept" for the accept arm).
fn verify_doc(name: &str, comment: &str, current: &TrustImage, object: &[u8]) -> String {
    let current_record = image_encode(current, TRUST_SEAL_COMMITTED).unwrap();
    let report = verify_manifest(current, object);
    let (expect, detail) = match &report.verdict {
        routeloom_provision::verify::Verdict::Accept(_) => ("accept".to_string(), "".to_string()),
        routeloom_provision::verify::Verdict::Refuse(e) => {
            (format!("{:?}", e.code), e.detail.to_string())
        }
    };
    format!(
        "{{\n  \"format\": \"routeloom-provisioning-golden-v1\",\n  \"kind\": \"manifest-verify\",\n  \"name\": \"{name}\",\n  \"comment\": \"{comment}\",\n  \"expect\": \"{expect}\",\n  \"expect_detail\": \"{detail}\",\n  \"current_record_hex\": \"{}\",\n  \"object_hex\": \"{}\"\n}}\n",
        hex_encode(&current_record),
        hex_encode(object),
    )
}

fn main() {
    let dir = golden_dir();
    fs::create_dir_all(dir.join("invalid")).unwrap();

    // --- keys.json: the fixed test key family ------------------------------
    let (root_a_secret, root_a_pub) = test_keypair(0x11);
    let (root_b_secret, root_b_pub) = test_keypair(0x22);
    let (auth_secret, auth_pub) = test_keypair(0x33);
    let (device_secret, device_pub) = test_keypair(0x55);
    let device_kid = credential_kid(&device_pub);
    write(
        &dir,
        "keys.json",
        &format!(
            "{{\n  \"format\": \"routeloom-provisioning-golden-v1\",\n  \"kind\": \"keys\",\n  \"name\": \"keys\",\n  \"comment\": \"test_keypair(seed) fixtures — secret = seed byte x32; TEST MATERIAL ONLY\",\n  \"root_a\": {{\"root_id\": \"{:016x}\", \"secret_hex\": \"{}\", \"pubkey_hex\": \"{}\"}},\n  \"root_b\": {{\"root_id\": \"{:016x}\", \"secret_hex\": \"{}\", \"pubkey_hex\": \"{}\"}},\n  \"authority\": {{\"authority_id\": \"{:016x}\", \"generation\": 1, \"secret_hex\": \"{}\", \"pubkey_hex\": \"{}\"}},\n  \"device\": {{\"node_id\": \"{:016x}\", \"secret_hex\": \"{}\", \"pubkey_hex\": \"{}\", \"kid_hex\": \"{}\"}}\n}}\n",
            ROOT_ID_A,
            hex_encode(&root_a_secret),
            hex_encode(&root_a_pub),
            ROOT_ID_B,
            hex_encode(&root_b_secret),
            hex_encode(&root_b_pub),
            AUTHORITY_ID,
            hex_encode(&auth_secret),
            hex_encode(&auth_pub),
            NODE_ID,
            hex_encode(&device_secret),
            hex_encode(&device_pub),
            hex_encode(&device_kid),
        ),
    );

    // --- trust images ------------------------------------------------------
    let epoch1 = image_epoch1();
    write(
        &dir,
        "image-epoch1.json",
        &image_doc(
            "image-epoch1",
            "genesis image: root A active, authority gen 1 active, empty revocation set",
            &epoch1,
        ),
    );
    let epoch2 = image_epoch2();
    write(
        &dir,
        "image-epoch2.json",
        &image_doc(
            "image-epoch2",
            "epoch 2: adds one credential revocation (node 0x77), floor unchanged",
            &epoch2,
        ),
    );

    // --- valid manifest -----------------------------------------------------
    let signer = root_a();
    let manifest_e2 = manifest_sign(&epoch2, &signer).unwrap();
    write(
        &dir,
        "manifest-epoch2.json",
        &verify_doc(
            "manifest-epoch2",
            "epoch-2 manifest signed by root A — accepts against image-epoch1",
            &epoch1,
            &manifest_e2,
        ),
    );

    // --- credential ----------------------------------------------------------
    let credential = DeviceCredential {
        network: NETWORK,
        node_id: NODE_ID,
        generation_base_session: 0,
        key_location: KeyLocation::NvsPlaintext,
        cred_status: CredStatus::Active,
        kid: device_kid,
        pubkey: device_pub,
        key_material: device_secret,
        grant: grant_fixture(NETWORK, NODE_ID, &device_kid, 3, 7, 11, 1000, 2000),
    };
    let cred_record = credential_record_encode(&credential, CRED_SEAL_COMMITTED).unwrap();
    write(
        &dir,
        "credential.json",
        &format!(
            "{{\n  \"format\": \"routeloom-provisioning-golden-v1\",\n  \"kind\": \"credential\",\n  \"name\": \"credential\",\n  \"comment\": \"RLC1 record for node 0x{NODE_ID:x} — grant signature bytes are zeros (grant verification is the membership workstream's, not this codec's)\",\n  \"network\": \"{NETWORK:016x}\",\n  \"node_id\": \"{NODE_ID:016x}\",\n  \"generation_base_session\": {},\n  \"key_location\": \"nvs-plaintext\",\n  \"cred_status\": \"active\",\n  \"kid_hex\": \"{}\",\n  \"pubkey_hex\": \"{}\",\n  \"cose_key_hex\": \"{}\",\n  \"grant_hex\": \"{}\",\n  \"record_hex\": \"{}\"\n}}\n",
            credential.generation_base_session,
            hex_encode(&credential.kid),
            hex_encode(&credential.pubkey),
            hex_encode(&credential_cose_key_encode(&device_pub)),
            hex_encode(&credential.grant),
            hex_encode(&cred_record),
        ),
    );

    // --- manufactured NVS set -------------------------------------------------
    let set = manufacture_nvs_set(&epoch1, Some(&credential), 0).unwrap();
    let mut entries = String::new();
    for (i, entry) in set.entries.iter().enumerate() {
        entries.push_str(if i == 0 { "\n" } else { ",\n" });
        match &entry.value {
            NvsValue::Blob(blob) => entries.push_str(&format!(
                "    {{\"namespace\": \"{}\", \"key\": \"{}\", \"type\": \"blob\", \"slot_bytes\": {}, \"data_hex\": \"{}\"}}",
                entry.namespace,
                entry.key,
                entry.slot_bytes().unwrap_or(0),
                hex_encode(blob),
            )),
            NvsValue::U32(value) => entries.push_str(&format!(
                "    {{\"namespace\": \"{}\", \"key\": \"{}\", \"type\": \"u32\", \"value\": {}}}",
                entry.namespace, entry.key, value,
            )),
        }
    }
    write(
        &dir,
        "nvs-set.json",
        &format!(
            "{{\n  \"format\": \"routeloom-provisioning-golden-v1\",\n  \"kind\": \"nvs-set\",\n  \"name\": \"nvs-set\",\n  \"comment\": \"P-A1 manufactured blob set for image-epoch1 + credential: twin committed records, rlboot session 0 (= first boot runs session 1)\",\n  \"entries\": [{entries}\n  ]\n}}\n"
        ),
    );

    // --- invalid vectors ------------------------------------------------------
    // Stale/replay: a correctly signed manifest at the committed epoch.
    let stale = manifest_sign(&epoch1, &signer).unwrap();
    write(
        &dir,
        "invalid/stale-epoch.json",
        &verify_doc(
            "stale-epoch",
            "valid signature but store_epoch == committed — ordinal compare refuses replay",
            &epoch1,
            &stale,
        ),
    );

    // Unknown anchor: signed under a kid no anchor in the image names.
    let foreign = FileRootSigner::from_secret(0x999, &test_keypair(0x22).0).unwrap();
    let unknown_anchor = manifest_sign(&epoch2, &foreign).unwrap();
    write(
        &dir,
        "invalid/unknown-anchor.json",
        &verify_doc(
            "unknown-anchor",
            "kid names no anchor in the committed image",
            &epoch1,
            &unknown_anchor,
        ),
    );

    // Disabled anchor: current carries root B disabled; B signs epoch 2.
    let mut committed_two = image_epoch1();
    committed_two.anchors.push(TrustAnchor {
        root_id: ROOT_ID_B,
        pubkey: root_b_pub,
        status: AnchorStatus::Disabled,
    });
    let signer_b = FileRootSigner::from_secret(ROOT_ID_B, &root_b_secret).unwrap();
    let disabled_anchor = manifest_sign(&epoch2, &signer_b).unwrap();
    write(
        &dir,
        "invalid/disabled-anchor.json",
        &verify_doc(
            "disabled-anchor",
            "kid names a DISABLED anchor — valid signature, still refused",
            &committed_two,
            &disabled_anchor,
        ),
    );

    // Tampered signature byte on an otherwise valid epoch-2 manifest.
    let mut bad_sig = manifest_e2.clone();
    let last = bad_sig.len() - 5;
    bad_sig[last] ^= 0x01;
    write(
        &dir,
        "invalid/bad-signature.json",
        &verify_doc(
            "bad-signature",
            "one signature byte flipped — ECDSA verify fails",
            &epoch1,
            &bad_sig,
        ),
    );

    // Foreign-network content: signed for network 8 end to end.
    let mut foreign_net = image_epoch2();
    foreign_net.network = 8;
    let foreign_net_obj = manifest_sign_with_aad(&foreign_net, &signer, 8).unwrap();
    write(
        &dir,
        "invalid/foreign-network.json",
        &verify_doc(
            "foreign-network",
            "content network 8 against committed network 7 — refused before signature work",
            &epoch1,
            &foreign_net_obj,
        ),
    );

    // AAD mismatch: network-7 content signed under a network-8 AAD.
    let aad_mismatch = manifest_sign_with_aad(&epoch2, &signer, 8).unwrap();
    write(
        &dir,
        "invalid/aad-mismatch.json",
        &verify_doc(
            "aad-mismatch",
            "signature binds AAD network 8; device derives 7 from its committed store — verify fails",
            &epoch1,
            &aad_mismatch,
        ),
    );

    // Zero active anchors in the result: signature verifies, semantic
    // validation refuses (the image would break its own signature chain).
    let mut suicidal = image_epoch2();
    suicidal.anchors[0].status = AnchorStatus::Disabled;
    let content = image_body_encode(&suicidal).unwrap();
    let protected = routeloom_provision::manifest::manifest_protected(ROOT_ID_A);
    let aad = routeloom_provision::manifest::manifest_aad(NETWORK);
    let sig =
        routeloom_provision::manifest::manifest_sig_structure(&protected, &aad, &content).unwrap();
    let signature = signer.sign(&sig).unwrap();
    let suicidal_obj = manifest_assemble(&content, ROOT_ID_A, &signature).unwrap();
    write(
        &dir,
        "invalid/no-active-anchor.json",
        &verify_doc(
            "no-active-anchor",
            "result image disables its only anchor — refused by image_validate after verify",
            &epoch1,
            &suicidal_obj,
        ),
    );

    // Generation-floor regression: committed floor 5, candidate floor 3.
    let mut floor5 = image_epoch1();
    floor5.min_authority_generation = 5;
    let mut regressed = image_epoch2();
    regressed.min_authority_generation = 3;
    let regressed_obj = manifest_sign(&regressed, &signer).unwrap();
    write(
        &dir,
        "invalid/floor-regression.json",
        &verify_doc(
            "floor-regression",
            "min_authority_generation 3 < committed floor 5 — floors never regress",
            &floor5,
            &regressed_obj,
        ),
    );

    // Truncated object: malformed envelope, ProtocolError before content.
    let truncated = &manifest_e2[..manifest_e2.len() - 20];
    write(
        &dir,
        "invalid/truncated.json",
        &verify_doc(
            "truncated",
            "object cut mid-signature — envelope parse refuses",
            &epoch1,
            truncated,
        ),
    );
}
