use routeloom_join::renew::{Commit, CutoverCommit, Head, Phase, Prepare, Receipt, RouteState};
use routeloom_provision::sdkv1::revocation::{revocation_object_verify, REVOCATION_OBJECT_MAX};
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::{test_keypair, FileRootSigner};

#[test]
fn signed_commit_binds_old_network_and_rrs_digest() {
    let (secret, pubkey) = test_keypair(0x55);
    let signer = FileRootSigner::from_secret(7, &secret).unwrap();
    let proof = CutoverCommit {
        site_id: 7,
        old_network: 0x0001_0000_002a,
        new_network: 0x0002_0000_002a,
        cutover_id: 4,
        revision: 1,
        gk_epoch: 19,
        rs_epoch: 22,
        rrs_sha256: [0x32; 32],
    };
    let object = proof.issue(&signer).unwrap();
    assert_eq!(object.len(), 155);
    assert_eq!(
        CutoverCommit::verify(&object, &pubkey, proof.old_network).unwrap(),
        (proof.clone(), true)
    );
    assert!(
        !CutoverCommit::verify(&object, &pubkey, proof.new_network)
            .unwrap()
            .1
    );
    let mut tampered = object.clone();
    tampered[50] ^= 1;
    assert!(
        !CutoverCommit::verify(&tampered, &pubkey, proof.old_network)
            .unwrap()
            .1
    );
    let head = Head {
        phase: Phase::Commit,
        cutover_id: 4,
        revision: 1,
        old_network: proof.old_network,
    };
    let wire = Commit {
        head,
        proof: &object,
        rrs: &[1, 2, 3],
    }
    .encode()
    .unwrap();
    assert_eq!(wire.len(), 28 + 155 + 3);
    let receipt = Receipt {
        head: Head {
            phase: Phase::Applied,
            ..head
        },
        new_network: proof.new_network,
        gk_epoch: 19,
        rs_epoch: 22,
        digest: [0xab; 32],
        status: 0,
    };
    assert_eq!(
        Receipt::decode(&receipt.encode().unwrap()).unwrap(),
        receipt
    );
}

#[test]
fn full_revocation_set_fits_cutover_commit() {
    let head = Head {
        phase: Phase::Commit,
        cutover_id: 4,
        revision: 1,
        old_network: 0x0001_0000_002a,
    };
    let proof = [0u8; 155];
    let rrs = vec![0u8; REVOCATION_OBJECT_MAX];
    let wire = Commit {
        head,
        proof: &proof,
        rrs: &rrs,
    }
    .encode()
    .unwrap();
    assert_eq!(wire.len(), 28 + proof.len() + REVOCATION_OBJECT_MAX);
}

#[test]
fn shared_cutover_vector_matches_all_four_phases() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/sdkv1-golden/valid/cutover_signed.json"
    );
    let source = std::fs::read_to_string(path).unwrap();
    let doc = routeloom_json::parse(&source).unwrap();
    let number = |key: &str| doc.get(key).unwrap().as_u64().unwrap();
    let bytes = |key: &str| {
        let value = doc.get(key).unwrap().as_str().unwrap();
        (0..value.len() / 2)
            .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let head = Head {
        phase: Phase::Prepare,
        cutover_id: number("cutover_id"),
        revision: number("revision") as u32,
        old_network: number("old_network"),
    };
    let site_cert = bytes("sitecert_hex");
    let member_cert = bytes("membercert_hex");
    let site_package = bytes("site_package_hex");
    let dams: [u8; 32] = bytes("dams_hex").try_into().unwrap();
    let prepare = Prepare {
        head,
        new_network: number("new_network"),
        site_cert: &site_cert,
        member_cert: &member_cert,
        site_package: &site_package,
        dams,
    };
    assert_eq!(prepare.encode().unwrap(), bytes("prepare_hex"));

    let proof = bytes("commit_proof_hex");
    let rrs = bytes("rrs_hex");
    let commit = Commit {
        head: Head {
            phase: Phase::Commit,
            ..head
        },
        proof: &proof,
        rrs: &rrs,
    };
    assert_eq!(commit.encode().unwrap(), bytes("commit_hex"));
    let secret: [u8; 32] = bytes("signer_secret_hex").try_into().unwrap();
    let pubkey: [u8; 64] = bytes("signer_pubkey_hex").try_into().unwrap();
    let signer = FileRootSigner::from_secret(number("site_id"), &secret).unwrap();
    let claim = CutoverCommit {
        site_id: number("site_id"),
        old_network: head.old_network,
        new_network: number("new_network"),
        cutover_id: head.cutover_id,
        revision: head.revision,
        gk_epoch: number("gk_epoch") as u32,
        rs_epoch: number("rs_epoch") as u32,
        rrs_sha256: bytes("rrs_sha256_hex").try_into().unwrap(),
    };
    assert_eq!(sha256(&rrs), claim.rrs_sha256);
    assert_eq!(sha256(&proof).to_vec(), bytes("commit_digest_hex"));
    let (set, verified) =
        revocation_object_verify(&rrs, &pubkey, number("site_id"), number("new_network")).unwrap();
    assert!(verified);
    assert_eq!(u64::from(set.rs_epoch), number("rs_epoch"));
    assert_eq!(claim.issue(&signer).unwrap(), proof);
    assert_eq!(
        CutoverCommit::verify(&proof, &pubkey, head.old_network).unwrap(),
        (claim, true)
    );

    for (phase, key, digest_key, rs_epoch) in [
        (Phase::Prepared, "prepared_hex", "prepare_digest_hex", 0),
        (
            Phase::Applied,
            "applied_hex",
            "commit_digest_hex",
            number("rs_epoch") as u32,
        ),
        (
            Phase::CommitStored,
            "commit_stored_hex",
            "commit_digest_hex",
            number("rs_epoch") as u32,
        ),
    ] {
        let receipt = Receipt {
            head: Head { phase, ..head },
            new_network: number("new_network"),
            gk_epoch: number("gk_epoch") as u32,
            rs_epoch,
            digest: bytes(digest_key).try_into().unwrap(),
            status: 0,
        };
        assert_eq!(receipt.encode().unwrap().to_vec(), bytes(key));
        assert_eq!(Receipt::decode(&bytes(key)).unwrap(), receipt);
    }
}

#[test]
fn route_state_query_and_reports_share_the_vector() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/sdkv1-golden/valid/cutover_signed.json"
    );
    let source = std::fs::read_to_string(path).unwrap();
    let doc = routeloom_json::parse(&source).unwrap();
    let number = |key: &str| doc.get(key).unwrap().as_u64().unwrap();
    let bytes = |key: &str| {
        let value = doc.get(key).unwrap().as_str().unwrap();
        (0..value.len() / 2)
            .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let head = Head {
        phase: Phase::RouteState,
        cutover_id: number("cutover_id"),
        revision: number("revision") as u32,
        old_network: number("old_network"),
    };
    let query = RouteState {
        head,
        mode: 0,
        status: 0,
        root: 0,
        parent: 0,
        boot: 0,
        route_stamp: 0,
        query_id: 41,
        valid_for_ms: 0,
    };
    assert_eq!(
        query.encode().unwrap().to_vec(),
        bytes("routestate_query_hex")
    );
    assert_eq!(
        RouteState::decode(&bytes("routestate_query_hex")).unwrap(),
        query
    );
    let report = RouteState {
        head,
        mode: 1,
        status: 0,
        root: number("routestate_root"),
        parent: number("routestate_parent"),
        boot: 7,
        route_stamp: 4242,
        query_id: 41,
        valid_for_ms: 30_000,
    };
    assert_eq!(
        report.encode().unwrap().to_vec(),
        bytes("routestate_report_hex")
    );
    assert_eq!(
        RouteState::decode(&bytes("routestate_report_hex")).unwrap(),
        report
    );
    let unavailable = RouteState {
        head,
        mode: 1,
        status: 1,
        root: 0,
        parent: 0,
        boot: 0,
        route_stamp: 0,
        query_id: 41,
        valid_for_ms: 0,
    };
    assert_eq!(
        unavailable.encode().unwrap().to_vec(),
        bytes("routestate_unavailable_hex")
    );
    assert_eq!(
        RouteState::decode(&bytes("routestate_unavailable_hex")).unwrap(),
        unavailable
    );
}

#[test]
fn route_state_rejects_noncanonical_shapes() {
    let head = Head {
        phase: Phase::RouteState,
        cutover_id: 9,
        revision: 1,
        old_network: 0x0001_0000_002a,
    };
    let query = RouteState {
        head,
        mode: 0,
        status: 0,
        root: 0,
        parent: 0,
        boot: 0,
        route_stamp: 0,
        query_id: 41,
        valid_for_ms: 0,
    };
    assert!(query.encode().is_ok());
    // Shape violations never encode.
    for mutated in [
        RouteState { mode: 2, ..query },
        RouteState { status: 1, ..query },
        RouteState { root: 1, ..query },
        RouteState {
            query_id: 0,
            ..query
        },
        RouteState {
            mode: 1,
            status: 2,
            ..query
        },
        RouteState {
            mode: 1,
            status: 0,
            root: 0,
            query_id: 41,
            ..query
        },
        RouteState {
            mode: 1,
            status: 1,
            parent: 1,
            ..query
        },
        RouteState {
            mode: 1,
            status: 1,
            valid_for_ms: 1,
            ..query
        },
    ] {
        assert!(mutated.encode().is_err());
    }
    // Wire violations never decode.
    let mut wire = query.encode().unwrap().to_vec();
    assert!(RouteState::decode(&wire[..59]).is_err());
    wire.push(0);
    assert!(RouteState::decode(&wire).is_err());
    wire.pop();
    wire[26] = 1;
    assert!(RouteState::decode(&wire).is_err());
    wire[26] = 0;
    wire[1] = Phase::Applied as u8;
    assert!(RouteState::decode(&wire).is_err());
}
