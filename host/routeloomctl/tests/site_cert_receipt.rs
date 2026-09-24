use std::process::Command;

use routeloom_provision::sdkv1::siteca::FileSiteCaSigner;
use routeloom_provision::signer::{hex_encode, test_keypair};

#[test]
fn site_cert_receipt_escapes_output_path() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-site-\"receipt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let key = dir.join("siteca.key");
    FileSiteCaSigner::from_secret(0x05CA_0000_0000_0001, &[0x51; 32])
        .unwrap()
        .save(&key)
        .unwrap();
    let (_, sak_pubkey) = test_keypair(0x53);
    let out = dir.join("sitecert.cwt");
    let result = Command::new(env!("CARGO_BIN_EXE_routeloomctl"))
        .args([
            "site-cert",
            "--ca-key",
            key.to_str().unwrap(),
            "--site-id",
            "5173000000000042",
            "--sak-pubkey",
            &hex_encode(&sak_pubkey),
            "--network-low32",
            "0a1b2c3d",
            "--site-epoch",
            "3",
            "--serial",
            "7",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let receipt = routeloom_json::parse(stdout.trim()).unwrap();
    assert_eq!(
        receipt.get("cert_file").and_then(|value| value.as_str()),
        out.to_str()
    );
    assert!(out.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn site_ca_keygen_receipt_escapes_output_path() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-ca-\"receipt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let out = dir.join("siteca.key");
    let result = Command::new(env!("CARGO_BIN_EXE_routeloomctl"))
        .args([
            "provision-siteca-keygen",
            "--site-ca-id",
            "05ca000000000001",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let receipt = routeloom_json::parse(stdout.trim()).unwrap();
    assert_eq!(
        receipt.get("key_file").and_then(|value| value.as_str()),
        out.to_str()
    );
    assert!(out.exists());
    std::fs::remove_dir_all(dir).unwrap();
}
