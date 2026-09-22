//! Offline RTM1 acceptance check — the host mirror of the §4.5.1 pipeline
//! (`trust_manifest_accept` + the `commit_image` preconditions), minus the
//! physical commit: an operator can check a manifest offline exactly the
//! way a device would decide, given the committed image the check runs
//! against. Every refusal carries the same [`Code`] the device's
//! `StatusCode` would report, so a verdict means the same thing on both
//! sides of the boundary.
//!
//! Device ordering, mirrored exactly:
//! 1. restricted envelope shape, object <= 2048;
//! 2. content-head decode: `network` equals the committed image's network,
//!    nonzero `store_epoch`, counts within caps, tables exactly sized;
//! 3. `store_epoch` strictly greater than the committed epoch (ordinal —
//!    u32 wrap is a re-provision event, never modular);
//! 4. `kid` names an anchor ACTIVE in the current image; R/S range + low-S
//!    canonicality; the signature verifies under the anchor's pubkey over
//!    `SHA-256(Sig_structure)` with the committed-network AAD;
//! 5. semantic checks the device's `commit_image` runs after the verify:
//!    `image_validate` (incl. >=1 ACTIVE anchor) and the
//!    `min_authority_generation` floor that never regresses.
//!
//! Store-state gates (`initialized`/`quarantined`/`uncertain`/`has_active`)
//! and the two-phase commit have no offline meaning — the caller supplies
//! the committed image and performs any physical write itself.

use crate::image::{find_anchor, image_body_decode, image_validate, AnchorStatus, TrustImage};
use crate::manifest::{manifest_aad, manifest_parse, manifest_sig_structure};
use crate::sha256::sha256;
use crate::signer::signature_range_check;
use crate::{err, Code, Error, Result};

/// The §4.5.1 verdict — the device's StatusCode vocabulary carried to the
/// operator. `Accept` is the `Ok` arm: it carries the candidate image the
/// device would commit (the same value `commit_image` would land).
#[derive(Clone, Debug)]
pub enum Verdict {
    /// Accepted — the candidate image that would become authoritative.
    Accept(TrustImage),
    /// Refused — `code` mirrors the device StatusCode and `detail` is the
    /// same static detail string the device path returns.
    Refuse(Error),
}

impl Verdict {
    pub fn accepted(&self) -> bool {
        matches!(self, Verdict::Accept(_))
    }

    /// The device-equivalent code: None when accepted, the refusal code
    /// otherwise (ProtocolError = malformed; Conflict = stale/replay;
    /// AuthorizationFailed = wrong network, unusable anchor, bad signature
    /// or a regressed floor; InvalidArgument = semantically invalid image).
    pub fn code(&self) -> Option<Code> {
        match self {
            Verdict::Accept(_) => None,
            Verdict::Refuse(error) => Some(error.code),
        }
    }

    /// The static detail string (`""` when accepted).
    pub fn detail(&self) -> &'static str {
        match self {
            Verdict::Accept(_) => "",
            Verdict::Refuse(error) => error.detail,
        }
    }
}

/// What the offline check learned about the object before the verdict —
/// the operator-facing context a report prints (all `None` when the
/// envelope itself was malformed).
#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub verdict: Verdict,
    /// kid the manifest names, once the envelope parsed.
    pub root_id: Option<u64>,
    /// Candidate `store_epoch`, once the content head decoded.
    pub claimed_epoch: Option<u32>,
    /// Candidate `network`, once the content head decoded.
    pub claimed_network: Option<u64>,
}

/// The offline §4.5.1 acceptance pipeline. `current` is the committed
/// trust image the check runs against — the equivalent of the device's
/// active store. It must itself pass `image_validate` (a committed image
/// always does); anything else is a caller bug, reported as
/// InvalidArgument rather than silently evaluated against.
pub fn verify_manifest(current: &TrustImage, object: &[u8]) -> VerifyReport {
    let mut report = VerifyReport {
        verdict: Verdict::Refuse(Error::new(Code::InternalError, "verdict unset")),
        root_id: None,
        claimed_epoch: None,
        claimed_network: None,
    };
    report.verdict = match run_pipeline(current, object, &mut report) {
        Ok(image) => Verdict::Accept(image),
        Err(error) => Verdict::Refuse(error),
    };
    report
}

/// The same check as a plain `Result` for callers that only want the
/// device-equivalent status — `Ok(candidate)` is the accept arm.
pub fn verify_manifest_accept(current: &TrustImage, object: &[u8]) -> Result<TrustImage> {
    match verify_manifest(current, object).verdict {
        Verdict::Accept(image) => Ok(image),
        Verdict::Refuse(error) => Err(error),
    }
}

fn run_pipeline(
    current: &TrustImage,
    object: &[u8],
    report: &mut VerifyReport,
) -> Result<TrustImage> {
    // Caller precondition: the committed image the check runs against is a
    // real one — the store guarantees this on-device.
    image_validate(current)?;

    // 1. Envelope shape (cheap parse; §4.5.1 rule 1).
    let parts = manifest_parse(object)?;
    report.root_id = Some(parts.root_id);

    // 2. Content head: structural decode, then the cheap semantic gates
    //    before any signature work (network equality, nonzero epoch,
    //    counts/tables — enforced inside the codec).
    let candidate = image_body_decode(parts.payload)?;
    report.claimed_epoch = Some(candidate.store_epoch);
    report.claimed_network = Some(candidate.network);
    if candidate.network != current.network {
        return err(Code::AuthorizationFailed, "manifest foreign network");
    }
    if candidate.store_epoch == 0 {
        return err(Code::ProtocolError, "manifest epoch zero");
    }

    // 3. Ordinal epoch compare — a manifest at or below the committed epoch
    //    is a harmless stale replay, denied without spending the verify.
    //    (commit_image re-checks against the proven epoch floor; offline the
    //    committed image IS the proven floor — a CRC-failed sibling's higher
    //    bound is storage evidence only the device sees.)
    if candidate.store_epoch <= current.store_epoch {
        return err(Code::Conflict, "manifest epoch not newer");
    }

    // 4. kid names an anchor ACTIVE in the CURRENT image (a manifest signed
    //    under a disabled anchor fails even with a valid signature).
    let anchor = find_anchor(current, parts.root_id)
        .filter(|a| a.status == AnchorStatus::Active)
        .ok_or(Error::new(
            Code::AuthorizationFailed,
            "manifest anchor unusable",
        ))?;

    // R/S range + low-S canonicality before the expensive point multiply —
    // the same rules the permit verifier applies.
    let signature: &[u8; 64] = parts
        .signature
        .try_into()
        .map_err(|_| Error::new(Code::ProtocolError, "manifest signature size"))?;
    signature_range_check(signature)
        .map_err(|_| Error::new(Code::AuthorizationFailed, "manifest signature range"))?;

    // The AAD binds the device's own committed network — never a transport
    // claim (§4.3.3).
    let aad = manifest_aad(current.network);
    let to_verify = manifest_sig_structure(parts.protected_bytes, &aad, parts.payload)?;
    let digest = sha256(&to_verify);
    if !verify_p256(&anchor.pubkey, &digest, signature) {
        return err(Code::AuthorizationFailed, "manifest signature invalid");
    }

    // 5-6. The commit_image semantic gates, in the device's order:
    //    image_validate (>=1 ACTIVE anchor retention lives inside it),
    //    the epoch floor re-check, then the generation floor.
    image_validate(&candidate)?;
    if candidate.store_epoch <= current.store_epoch {
        return err(Code::Conflict, "trust image epoch not newer");
    }
    if candidate.min_authority_generation < current.min_authority_generation {
        // Floors never regress: a lower bound would re-admit permits signed
        // under already-excluded key generations.
        return err(
            Code::AuthorizationFailed,
            "authority generation floor regressed",
        );
    }
    Ok(candidate)
}

/// ECDSA P-256/SHA-256 verify — the host stand-in for `uECC_verify` over
/// the already-computed Sig_structure digest. R || S raw signature, X || Y
/// public key.
fn verify_p256(pubkey: &[u8; 64], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey);
    let Ok(key) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    // The device hashes the Sig_structure once and verifies the digest —
    // verify_prehash, not the message path, keeps the semantics identical.
    key.verify_prehash(digest, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{KeyStatus, TrustAnchor, TrustImage, TrustKeyRecord};
    use crate::manifest::{manifest_assemble, manifest_sign, manifest_sign_with_aad};
    use crate::signer::{be32_cmp, test_keypair, FileRootSigner, RootSigner, SECP256R1_ORDER};

    const ROOT_ID_A: u64 = 0x100;
    const ROOT_ID_B: u64 = 0x200;
    const NETWORK: u64 = 7;

    fn base_image() -> (TrustImage, FileRootSigner) {
        let (root_secret, root_pub) = test_keypair(0x11);
        let (_, auth_pub) = test_keypair(0x33);
        let mut image = TrustImage {
            store_epoch: 1,
            min_authority_generation: 1,
            network: NETWORK,
            deployment_id: 0xDE9,
            ..TrustImage::default()
        };
        image.anchors.push(TrustAnchor {
            root_id: ROOT_ID_A,
            pubkey: root_pub,
            status: AnchorStatus::Active,
        });
        image.keys.push(TrustKeyRecord {
            authority_id: 0xA17,
            generation: 1,
            profile: 1,
            role: 1,
            status: KeyStatus::Active,
            scope: 0,
            pubkey: auth_pub,
        });
        let signer = FileRootSigner::from_secret(ROOT_ID_A, &root_secret).unwrap();
        (image, signer)
    }

    fn next_image(base: &TrustImage) -> TrustImage {
        let mut next = base.clone();
        next.store_epoch = 2;
        next
    }

    #[test]
    fn accept_happy_path() {
        let (current, signer) = base_image();
        let mut next = next_image(&current);
        next.min_authority_generation = 2;
        let object = manifest_sign(&next, &signer).unwrap();
        let report = verify_manifest(&current, &object);
        assert_eq!(report.root_id, Some(ROOT_ID_A));
        assert_eq!(report.claimed_epoch, Some(2));
        match report.verdict {
            Verdict::Accept(image) => {
                assert_eq!(image.store_epoch, 2);
                assert_eq!(image.min_authority_generation, 2);
            }
            Verdict::Refuse(e) => panic!("refused: {e}"),
        }
    }

    #[test]
    fn stale_and_replay_epochs() {
        let (current, signer) = base_image();
        for epoch in [0_u32, 1] {
            let mut image = next_image(&current);
            image.store_epoch = epoch;
            if epoch == 0 {
                // epoch-0 content cannot be minted by manifest_sign
                // (validation); build the object structurally instead.
                let content = crate::image::image_body_encode(&image).unwrap();
                let object = manifest_assemble(&content, ROOT_ID_A, &[0_u8; 64]).unwrap();
                assert_eq!(
                    verify_manifest_accept(&current, &object).unwrap_err().code,
                    Code::ProtocolError
                );
                continue;
            }
            let object = manifest_sign(&image, &signer).unwrap();
            assert_eq!(
                verify_manifest_accept(&current, &object).unwrap_err().code,
                Code::Conflict
            );
        }
    }

    #[test]
    fn foreign_network_denied() {
        let (current, signer) = base_image();
        let mut next = next_image(&current);
        next.network = 8;
        // Minting needs a valid image — epoch/network both nonzero here.
        let object = manifest_sign_with_aad(&next, &signer, 8).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );
    }

    #[test]
    fn anchor_policy() {
        let (current, _signer) = base_image();
        let next = next_image(&current);

        // kid names no anchor in the committed image.
        let (other_secret, _) = test_keypair(0x22);
        let foreign_signer = FileRootSigner::from_secret(0x999, &other_secret).unwrap();
        let object = manifest_sign(&next, &foreign_signer).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );

        // kid names a DISABLED anchor — fails even with a valid signature.
        let mut committed = current.clone();
        committed.anchors.push(TrustAnchor {
            root_id: ROOT_ID_B,
            pubkey: other_secret_pubkey(),
            status: AnchorStatus::Disabled,
        });
        let signer_b = FileRootSigner::from_secret(ROOT_ID_B, &other_secret).unwrap();
        let object = manifest_sign(&next, &signer_b).unwrap();
        assert_eq!(
            verify_manifest_accept(&committed, &object)
                .unwrap_err()
                .code,
            Code::AuthorizationFailed
        );
    }

    fn other_secret_pubkey() -> [u8; 64] {
        test_keypair(0x22).1
    }

    #[test]
    fn bad_signature_denied() {
        let (current, signer) = base_image();
        let next = next_image(&current);

        // Signed by an intruder's key under the real anchor's kid.
        let (intruder_secret, _) = test_keypair(0xEE);
        let intruder = FileRootSigner::from_secret(ROOT_ID_A, &intruder_secret).unwrap();
        let object = manifest_sign(&next, &intruder).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );

        // Tampered signature byte.
        let mut object = manifest_sign(&next, &signer).unwrap();
        let last = object.len() - 10;
        object[last] ^= 0x01;
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );

        // R = S = 0: range rule fires before the verify.
        let content = crate::image::image_body_encode(&next).unwrap();
        let object = manifest_assemble(&content, ROOT_ID_A, &[0_u8; 64]).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );

        // S = n: out of range.
        let mut signature = [0_u8; 64];
        signature[0] = 1; // R = 1
        signature[32..].copy_from_slice(&SECP256R1_ORDER);
        let object = manifest_assemble(&content, ROOT_ID_A, &signature).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );

        // High-S form of an otherwise valid signature: malleability refused.
        let object = manifest_sign(&next, &signer).unwrap();
        let parts = manifest_parse(&object).unwrap();
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(parts.signature);
        let mut flipped = SECP256R1_ORDER;
        let s: &[u8; 32] = signature[32..].try_into().unwrap();
        be32_sub(&mut flipped, s);
        signature[32..].copy_from_slice(&flipped);
        let object = manifest_assemble(parts.payload, ROOT_ID_A, &signature).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );
    }

    /// Big-endian 32-byte a -= b — the test_provisioning.hpp be32_sub mirror.
    fn be32_sub(a: &mut [u8; 32], b: &[u8; 32]) {
        let mut borrow = 0_i32;
        for i in (0..32).rev() {
            let diff = a[i] as i32 - b[i] as i32 - borrow;
            a[i] = diff as u8;
            borrow = if diff < 0 { 1 } else { 0 };
        }
        debug_assert!(be32_cmp(a, &SECP256R1_ORDER) < 0);
    }

    #[test]
    fn aad_binding() {
        // A signature over a foreign-network AAD fails even though the
        // content network matches the committed image.
        let (current, signer) = base_image();
        let next = next_image(&current);
        let object = manifest_sign_with_aad(&next, &signer, 8).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );
    }

    #[test]
    fn semantic_floor_regression() {
        let (mut current, signer) = base_image();
        current.min_authority_generation = 5;
        let mut regressed = next_image(&current);
        regressed.min_authority_generation = 3;
        let object = manifest_sign(&regressed, &signer).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::AuthorizationFailed
        );
    }

    #[test]
    fn broken_chain_refused() {
        // An image that leaves zero active anchors is refused by the
        // commit-side validation even though the signature verifies.
        let (current, signer) = base_image();
        let mut suicidal = next_image(&current);
        suicidal.anchors[0].status = AnchorStatus::Disabled;
        // manifest_sign validates and refuses — build the object directly,
        // the way a raw-signing operator could still emit it.
        let content = crate::image::image_body_encode(&suicidal).unwrap();
        let protected = crate::manifest::manifest_protected(ROOT_ID_A);
        let aad = manifest_aad(NETWORK);
        let to_sign = crate::manifest::manifest_sig_structure(&protected, &aad, &content).unwrap();
        let signature = signer.sign(&to_sign).unwrap();
        let object = manifest_assemble(&content, ROOT_ID_A, &signature).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::InvalidArgument
        );
    }

    #[test]
    fn config_off_is_legal() {
        // Zero active config keys is a legal state (§4.5.1 rule 5
        // constrains anchors only).
        let (current, signer) = base_image();
        let mut off = next_image(&current);
        off.keys.clear();
        let object = manifest_sign(&off, &signer).unwrap();
        assert!(verify_manifest_accept(&current, &object).is_ok());
    }

    #[test]
    fn overcap_content_is_malformed() {
        let (current, signer) = base_image();
        let next = next_image(&current);
        let mut content = crate::image::image_body_encode(&next).unwrap();
        content[25] = 3; // anchor_count over the 2-cap — structural reject
        let object = manifest_sign(&next, &signer).unwrap();
        let parts = manifest_parse(&object).unwrap();
        let object = manifest_assemble(&content, ROOT_ID_A, parts.signature).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::ProtocolError
        );
    }

    #[test]
    fn malformed_object() {
        let (current, signer) = base_image();
        let mut object = manifest_sign(&next_image(&current), &signer).unwrap();
        object[0] = 0xD3;
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::ProtocolError
        );
        let huge = vec![0_u8; crate::manifest::TRUST_MANIFEST_OBJECT_MAX + 1];
        assert_eq!(
            verify_manifest_accept(&current, &huge).unwrap_err().code,
            Code::ProtocolError
        );
    }

    #[test]
    fn invalid_current_image_is_caller_bug() {
        let (mut current, signer) = base_image();
        current.network = 0; // not a committed-shape image
        let object = manifest_sign(&next_image(&base_image().0), &signer).unwrap();
        assert_eq!(
            verify_manifest_accept(&current, &object).unwrap_err().code,
            Code::InvalidArgument
        );
    }
}
