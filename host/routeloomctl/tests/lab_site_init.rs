use std::{fs, process::Command};

#[test]
fn lab_site_init_is_private_unique_and_requires_written_inventory() {
    let parent = std::env::temp_dir().join(format!(
        "routeloom-lab-init-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&parent).unwrap();
    let spec = parent.join("spec.json");
    fs::write(&spec, r#"{"format":"routeloom-lab-site-spec-v1","site_id":"0123456789abcdef","device_ca_id":"1023456789abcdef","site_ca_id":"2023456789abcdef","network_low32":"12345678","channel":1,"gateways":["3023456789abcdef"]}"#).unwrap();
    let site = parent.join("site");
    let init = || {
        Command::new(env!("CARGO_BIN_EXE_routeloomctl"))
            .args([
                "lab-site-init",
                "--spec",
                spec.to_str().unwrap(),
                "--out",
                site.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    assert!(init().status.success());
    let original = fs::read(site.join("keys/device-ca.key")).unwrap();
    let other_spec = parent.join("other.json");
    let text = fs::read_to_string(&spec)
        .unwrap()
        .replace("0123456789abcdef", "4123456789abcdef")
        .replace("1023456789abcdef", "5023456789abcdef")
        .replace("2023456789abcdef", "6023456789abcdef");
    fs::write(&other_spec, text).unwrap();
    let other = parent.join("other-site");
    assert!(Command::new(env!("CARGO_BIN_EXE_routeloomctl"))
        .args([
            "lab-site-init",
            "--spec",
            other_spec.to_str().unwrap(),
            "--out",
            other.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert_ne!(
        fs::read(other.join("keys/device-ca.key")).unwrap(),
        original
    );
    assert_ne!(
        fs::read(other.join("keys/site-ca.key")).unwrap(),
        fs::read(site.join("keys/site-ca.key")).unwrap()
    );
    assert!(!init().status.success());
    assert_eq!(fs::read(site.join("keys/device-ca.key")).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [&site, &site.join("keys")] {
            assert_eq!(
                fs::metadata(dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for name in [
            "keys/device-ca.key",
            "keys/site-ca.key",
            "sak.key",
            "usb-dev-secret.key",
            "inventory.db",
            "lab-manifest.json",
        ] {
            assert_eq!(
                fs::metadata(site.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let ledger = parent.join("ledger.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_routeloomctl"))
        .args([
            "lab-inventory-import",
            "--site",
            site.to_str().unwrap(),
            "--ledger",
            ledger.to_str().unwrap(),
            "--node",
            "3023456789abcdef",
            "--role",
            "gateway",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "issued or missing receipt must not enable enrollment"
    );
    // An interrupted publish resumes with the same CA; a recorded but
    // missing key is never silently regenerated.
    let journal = site.join("lab-init.journal");
    let recorded = fs::read_to_string(&journal).unwrap();
    fs::write(&journal, recorded.strip_suffix("complete\n").unwrap()).unwrap();
    fs::remove_file(site.join("lab-manifest.json")).unwrap();
    assert!(init().status.success());
    assert_eq!(fs::read(site.join("keys/device-ca.key")).unwrap(), original);
    let recorded = fs::read_to_string(&journal).unwrap();
    fs::write(&journal, recorded.strip_suffix("complete\n").unwrap()).unwrap();
    fs::remove_file(site.join("lab-manifest.json")).unwrap();
    fs::remove_file(site.join("keys/device-ca.key")).unwrap();
    assert!(!init().status.success());
    assert!(!site.join("keys/device-ca.key").exists());
    let _ = fs::remove_dir_all(parent);
}
