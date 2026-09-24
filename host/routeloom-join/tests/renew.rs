use routeloom_join::renew::{Commit, CutoverCommit, Head, Phase, Receipt};
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
