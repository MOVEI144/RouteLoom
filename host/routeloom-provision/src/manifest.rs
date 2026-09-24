//! `RTM1` trust manifest object — byte-for-byte mirror of
//! `components/routeloom/src/trust_manifest.cpp`
//! (04-provisioning-lifecycle.md §4.3.3, §4.5.1). The in-band trust-update
//! unit is a COMPLETE replacement image: the signed payload is
//! byte-for-byte the RLT1 semantic content — RLT1 bytes
//! `[16, used_len-4)` — so verification, persistence and catch-up share
//! one codec (`crate::image::{image_body_encode, image_body_decode}`) and
//! one truth.
//!
//! Envelope: the same restricted COSE_Sign1 shape as the
//! RLCP1_COSE_ESP256 permit profile (tag 18, array(4), canonical protected
//! `{1:-9, 4:bstr8}`, empty unprotected map, raw `R || S` signature with
//! the low-S rule), with two differences: the kid names a deployment ROOT
//! ANCHOR (`root_id`) rather than a config authority, and the external AAD
//! is `"RouteLoom/trust-manifest/v1" || NUL || network u64` (36 bytes)
//! bound to the device's own committed network — never transport claims.

use crate::cbor;
use crate::image::{image_body_encode, image_validate, TrustImage, TRUST_IMAGE_CONTENT_MAX};
use crate::sha256::sha256;
use crate::signer::RootSigner;
use crate::{err, Code, Error, Result};

/// Maximum object: the shared `kAuthenticatedObjectMax` wire bound.
pub const TRUST_MANIFEST_OBJECT_MAX: usize = 2048;
/// The AAD domain string INCLUDING the NUL terminator the device writes
/// (`sizeof(kTrustManifestDomain)`).
pub const TRUST_MANIFEST_DOMAIN: &[u8; 28] = b"RouteLoom/trust-manifest/v1\0";
/// "RouteLoom/trust-manifest/v1" (27) || NUL || network u64 — 36 bytes.
pub const TRUST_MANIFEST_AAD_SIZE: usize = 36;
/// Sig_structure bound: array4 + "Signature1" + bstr(13) + bstr(36) +
/// bstr(<=1664) — `kTrustManifestSigMax`.
pub const TRUST_MANIFEST_SIG_MAX: usize = TRUST_IMAGE_CONTENT_MAX + 96;
/// a2 {1:-9, 4:h'kid8'} — the only protected shape the profile admits.
pub const TRUST_MANIFEST_PROTECTED_SIZE: usize = 13;
/// Raw R || S — `kCoseSignatureSize`.
pub const COSE_SIGNATURE_SIZE: usize = 64;

/// Smallest object the device parser admits: 84 bytes of fixed envelope
/// overhead + the smallest legal payload.
const MANIFEST_OBJECT_MIN: usize = 86;

/// The protected header's fixed head: map(2), label 1, alg -9 (ESP256),
/// label 4, bstr(8) kid.
const PROTECTED_HEAD: [u8; 5] = [0xA2, 0x01, 0x28, 0x04, 0x48];

/// The device's expected external AAD: the domain string + NUL + the
/// COMMITTED network (§4.3.3 — supplied from the store, never transport).
/// `network` is the FULL NetworkId (deployment generation in upper bits).
pub fn manifest_aad(network: u64) -> [u8; TRUST_MANIFEST_AAD_SIZE] {
    let mut out = [0_u8; TRUST_MANIFEST_AAD_SIZE];
    out[..28].copy_from_slice(TRUST_MANIFEST_DOMAIN);
    out[28..].copy_from_slice(&network.to_be_bytes());
    out
}

/// The canonical protected header for a `root_id`
/// (`a2 01 28 04 48 <id:8>`): the only protected shape the restricted
/// profile admits.
pub fn manifest_protected(root_id: u64) -> [u8; TRUST_MANIFEST_PROTECTED_SIZE] {
    let mut out = [0_u8; TRUST_MANIFEST_PROTECTED_SIZE];
    out[..5].copy_from_slice(&PROTECTED_HEAD);
    out[5..].copy_from_slice(&root_id.to_be_bytes());
    out
}

/// Result of the cheap envelope parse — kept separate from the crypto
/// verdict so a malformed object is an ERROR while a well-formed object
/// that fails authorization is a denial.
#[derive(Clone, Copy, Debug)]
pub struct TrustManifestParts<'a> {
    /// Exact signed protected bstr content (13 bytes).
    pub protected_bytes: &'a [u8],
    /// kid — must name an ACTIVE anchor.
    pub root_id: u64,
    /// RLT1 content bytes (borrowed from the object).
    pub payload: &'a [u8],
    /// R || S, 64 bytes.
    pub signature: &'a [u8],
}

/// Parse the restricted RTM1 envelope shape. Cheap checks only — no
/// crypto. Any deviation from the fixed profile is ProtocolError.
pub fn manifest_parse(object: &[u8]) -> Result<TrustManifestParts<'_>> {
    // 84 bytes of fixed envelope overhead + the smallest legal payload.
    if object.len() < MANIFEST_OBJECT_MIN || object.len() > TRUST_MANIFEST_OBJECT_MAX {
        return err(Code::ProtocolError, "manifest object size");
    }
    let mut pos = 0;
    cbor::expect_u8(object, &mut pos, 0xD2, "manifest tag18")?;
    cbor::expect_u8(object, &mut pos, 0x84, "manifest array4")?;
    let protected_bstr = cbor::read_bstr(object, &mut pos, "manifest protected")?;
    // Byte-exact protected header: map2 {alg:-9, kid:bstr8} canonical order.
    if protected_bstr.len() != TRUST_MANIFEST_PROTECTED_SIZE
        || protected_bstr[..5] != PROTECTED_HEAD
    {
        return err(Code::ProtocolError, "manifest protected shape");
    }
    let root_id = u64::from_be_bytes(protected_bstr[5..13].try_into().expect("8"));
    cbor::expect_u8(object, &mut pos, 0xA0, "manifest unprotected empty")?;
    let payload = cbor::read_bstr(object, &mut pos, "manifest payload")?;
    if payload.is_empty() || payload.len() > TRUST_IMAGE_CONTENT_MAX {
        return err(Code::ProtocolError, "manifest payload bounds");
    }
    let signature = cbor::read_bstr(object, &mut pos, "manifest signature")?;
    if signature.len() != COSE_SIGNATURE_SIZE || pos != object.len() {
        return err(Code::ProtocolError, "manifest signature/trailer");
    }
    Ok(TrustManifestParts {
        protected_bytes: protected_bstr,
        root_id,
        payload,
        signature,
    })
}

/// Sig_structure = `84 6a "Signature1" bstr(protected) bstr(external_aad)
/// bstr(payload)` for the restricted COSE_Sign1 profile the trust
/// manifest AND the RLCP1 config permit/recovery envelopes share (same
/// tag/array/protected shape, same low-S rule — only the kid namespace
/// and the external AAD differ). The AAD must be the profile's own
/// expected context (36 B manifest, 45 B permit, 46 B recovery) —
/// wire-supplied context is never accepted.
pub fn cose_sig_structure(
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if protected_bytes.len() != TRUST_MANIFEST_PROTECTED_SIZE
        || external_aad.is_empty()
        || external_aad.len() > 64
        || payload.is_empty()
        || payload.len() > TRUST_IMAGE_CONTENT_MAX
    {
        return err(Code::InvalidArgument, "cose sig_structure fields");
    }
    let mut out = Vec::with_capacity(external_aad.len() + payload.len() + 32);
    out.push(0x84); // array(4)
    out.push(0x60 + 10); // "Signature1" text(10)
    out.extend_from_slice(b"Signature1");
    cbor::write_bstr(&mut out, protected_bytes);
    cbor::write_bstr(&mut out, external_aad);
    cbor::write_bstr(&mut out, payload);
    debug_assert!(out.len() <= TRUST_MANIFEST_SIG_MAX + 64);
    Ok(out)
}

/// Sig_structure = `84 6a "Signature1" bstr(protected) bstr(external_aad)
/// bstr(payload)`. The AAD must be exactly the TRUST_MANIFEST_AAD_SIZE
/// value from [`manifest_aad`] — wire-supplied context is never accepted.
pub fn manifest_sig_structure(
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if external_aad.len() != TRUST_MANIFEST_AAD_SIZE {
        return err(Code::InvalidArgument, "manifest sig_structure fields");
    }
    let out = cose_sig_structure(protected_bytes, external_aad, payload)
        .map_err(|_| Error::new(Code::InvalidArgument, "manifest sig_structure fields"))?;
    debug_assert!(out.len() <= TRUST_MANIFEST_SIG_MAX);
    Ok(out)
}

/// Assemble a complete RTM1 object: envelope around already-computed
/// content + signature. The host RootSigner / test path uses this after
/// signing `sha256(sig_structure)` with the root private key; the device
/// never signs manifests.
pub fn manifest_assemble(content: &[u8], root_id: u64, signature: &[u8]) -> Result<Vec<u8>> {
    if content.is_empty()
        || content.len() > TRUST_IMAGE_CONTENT_MAX
        || signature.len() != COSE_SIGNATURE_SIZE
    {
        return err(Code::InvalidArgument, "manifest assemble fields");
    }
    let protected_bytes = manifest_protected(root_id);
    let mut out = Vec::with_capacity(content.len() + 88);
    out.push(0xD2); // tag 18
    out.push(0x84); // array(4)
    cbor::write_bstr(&mut out, &protected_bytes);
    out.push(0xA0); // empty unprotected map
    cbor::write_bstr(&mut out, content);
    cbor::write_bstr(&mut out, signature);
    debug_assert!(out.len() <= TRUST_MANIFEST_OBJECT_MAX);
    Ok(out)
}

/// Mint a signed manifest for `image` under `signer`'s root anchor — the
/// §4.3.3 production path: the content is the RLT1 body, the AAD binds the
/// image's own network (the only network a device can ever accept it on —
/// rule 2 rejects foreign-network content before the signature leg).
/// Validates the image semantically first: an image that could never
/// commit is never minted.
pub fn manifest_sign(image: &TrustImage, signer: &dyn RootSigner) -> Result<Vec<u8>> {
    manifest_sign_with_aad(image, signer, image.network)
}

/// [`manifest_sign`] with an explicit AAD network — for producing the
/// negative test vector where the signature binds a network the content
/// does not name (the device still derives the AAD from ITS committed
/// store, so this is only ever a fixture for the AAD-binding check).
pub fn manifest_sign_with_aad(
    image: &TrustImage,
    signer: &dyn RootSigner,
    aad_network: u64,
) -> Result<Vec<u8>> {
    image_validate(image)?;
    let content = image_body_encode(image)?;
    let protected_bytes = manifest_protected(signer.root_id());
    let aad = manifest_aad(aad_network);
    let to_sign = manifest_sig_structure(&protected_bytes, &aad, &content)?;
    let signature = signer.sign(&to_sign)?;
    manifest_assemble(&content, signer.root_id(), &signature)
}

/// SHA-256 over a Sig_structure — the digest the signer and the device's
/// `uECC_verify` share.
pub fn manifest_digest(
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<[u8; 32]> {
    Ok(sha256(&manifest_sig_structure(
        protected_bytes,
        external_aad,
        payload,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{image_body_decode, AnchorStatus, TrustAnchor};
    use crate::signer::{test_keypair, FileRootSigner};

    fn image(epoch: u32, network: u64, root_pub: [u8; 64], root_id: u64) -> TrustImage {
        TrustImage {
            store_epoch: epoch,
            min_authority_generation: 1,
            network,
            deployment_id: 0xDE9,
            anchors: vec![TrustAnchor {
                root_id,
                pubkey: root_pub,
                status: AnchorStatus::Active,
            }],
            ..TrustImage::default()
        }
    }

    #[test]
    fn aad_and_protected_layout() {
        let aad = manifest_aad(0x0102_0304_0506_0708);
        assert_eq!(aad.len(), 36);
        assert_eq!(&aad[..27], b"RouteLoom/trust-manifest/v1");
        assert_eq!(aad[27], 0); // NUL terminator included
        assert_eq!(aad[28], 0x01);
        assert_eq!(aad[35], 0x08);

        let protected = manifest_protected(0x0102_0304_0506_0708);
        assert_eq!(protected.len(), 13);
        assert_eq!(&protected[..5], &[0xA2, 0x01, 0x28, 0x04, 0x48]);
        assert_eq!(protected[5], 0x01);
        assert_eq!(protected[12], 0x08);
    }

    #[test]
    fn cose_sig_structure_shares_the_manifest_shape() {
        let protected = manifest_protected(0x42);
        let aad36 = manifest_aad(7);
        let payload = [9_u8; 64];
        // The manifest leg is exactly the shared construction at 36 B AAD.
        assert_eq!(
            manifest_sig_structure(&protected, &aad36, &payload).unwrap(),
            cose_sig_structure(&protected, &aad36, &payload).unwrap()
        );
        // The permit (45 B) and recovery (46 B) AADs the config issuer
        // signs under are admitted by the shared leg, never by manifests.
        for aad_len in [45_usize, 46] {
            let aad = vec![0xA5_u8; aad_len];
            let shared = cose_sig_structure(&protected, &aad, &payload).unwrap();
            assert_eq!(&shared[13..26], &protected);
            assert!(manifest_sig_structure(&protected, &aad, &payload).is_err());
        }
        assert!(cose_sig_structure(&protected, &[], &payload).is_err());
        assert!(cose_sig_structure(&protected, &[0_u8; 65], &payload).is_err());
    }

    #[test]
    fn sig_structure_layout() {
        let protected = manifest_protected(0x100);
        let aad = manifest_aad(7);
        let payload = [1, 2, 3, 4];
        let sig = manifest_sig_structure(&protected, &aad, &payload).unwrap();
        // 84 6a "Signature1" 4d <protected:13> 58 24 <aad:36> 44 <payload:4>
        assert_eq!(sig[0], 0x84);
        assert_eq!(sig[1], 0x6A);
        assert_eq!(&sig[2..12], b"Signature1");
        assert_eq!(sig[12], 0x4D);
        assert_eq!(&sig[13..26], &protected);
        assert_eq!(sig[26], 0x58);
        assert_eq!(sig[27], 36);
        assert_eq!(&sig[28..64], &aad);
        assert_eq!(sig[64], 0x44);
        assert_eq!(sig.len(), 65 + 4);
        // Wrong-size inputs refused.
        assert!(manifest_sig_structure(&protected[..12], &aad, &payload).is_err());
        assert!(manifest_sig_structure(&protected, &payload, &payload).is_err());
        assert!(manifest_sig_structure(&protected, &aad, &[]).is_err());
    }

    #[test]
    fn assemble_parse_roundtrip() {
        let (_, root_pub) = test_keypair(0x11);
        let (secret, _) = test_keypair(0x11);
        let signer = FileRootSigner::from_secret(0x100, &secret).unwrap();
        let image = image(2, 7, root_pub, 0x100);
        let object = manifest_sign(&image, &signer).unwrap();
        assert!(object.len() <= TRUST_MANIFEST_OBJECT_MAX);

        let parts = manifest_parse(&object).unwrap();
        assert_eq!(parts.root_id, 0x100);
        assert_eq!(parts.protected_bytes.len(), TRUST_MANIFEST_PROTECTED_SIZE);
        assert_eq!(parts.signature.len(), COSE_SIGNATURE_SIZE);
        // The payload is byte-for-byte the RLT1 body — the shared truth.
        let content = image_body_encode(&image).unwrap();
        assert_eq!(parts.payload, &content[..]);
        let decoded = image_body_decode(parts.payload).unwrap();
        assert_eq!(decoded.store_epoch, 2);
    }

    #[test]
    fn parse_malformed() {
        let (_, root_pub) = test_keypair(0x11);
        let (secret, _) = test_keypair(0x11);
        let signer = FileRootSigner::from_secret(0x100, &secret).unwrap();
        let base = manifest_sign(&image(2, 7, root_pub, 0x100), &signer).unwrap();

        let expect_err = |object: &[u8]| {
            assert!(manifest_parse(object).is_err());
        };
        expect_err(&base[..50]); // undersized
        expect_err(&vec![0_u8; TRUST_MANIFEST_OBJECT_MAX + 1]); // oversized
        {
            let mut m = base.clone();
            m[0] = 0xD3;
            expect_err(&m); // tag
        }
        {
            let mut m = base.clone();
            m[1] = 0x83;
            expect_err(&m); // array3
        }
        {
            let mut m = base.clone();
            m[2] = 0x58;
            m[3] = 13;
            expect_err(&m); // non-minimal protected header form
        }
        {
            let mut m = base.clone();
            m[3] = 0xA3;
            expect_err(&m); // protected map(3)
        }
        {
            let mut m = base.clone();
            m[2] = 0x4C;
            expect_err(&m); // protected bstr(12) wrong length
        }
        {
            let mut m = base.clone();
            m[16] = 0xA1;
            expect_err(&m); // non-empty unprotected map
        }
        {
            let mut m = base.clone();
            m.push(0x00);
            expect_err(&m); // trailing byte
        }
        expect_err(&base[..base.len() - 1]); // truncated
                                             // Empty payload bstr is a structural violation — and lands under
                                             // the 86-byte object floor either way.
        let mut crafted = Vec::new();
        crafted.push(0xD2);
        crafted.push(0x84);
        cbor::write_bstr(&mut crafted, &manifest_protected(0x100));
        crafted.push(0xA0);
        cbor::write_bstr(&mut crafted, &[]);
        cbor::write_bstr(&mut crafted, &[0_u8; 64]);
        assert!(crafted.len() < MANIFEST_OBJECT_MIN);
        expect_err(&crafted);
    }

    #[test]
    fn assemble_validation() {
        let content = [1, 2, 3, 4];
        let sig = [0_u8; 64];
        let out = manifest_assemble(&content, 0x100, &sig).unwrap();
        assert_eq!(out[0], 0xD2);
        assert_eq!(out[1], 0x84);
        assert!(manifest_assemble(&[], 0x100, &sig).is_err());
        assert!(manifest_assemble(&content, 0x100, &sig[..63]).is_err());
        assert!(manifest_assemble(&content, 0x100, &[]).is_err());
    }

    #[test]
    fn sign_refuses_invalid_image() {
        let (_, root_pub) = test_keypair(0x11);
        let (secret, _) = test_keypair(0x11);
        let signer = FileRootSigner::from_secret(0x100, &secret).unwrap();
        // Epoch zero can never commit — the tool refuses to mint it.
        let bad = image(0, 7, root_pub, 0x100);
        assert_eq!(
            manifest_sign(&bad, &signer).unwrap_err().code,
            Code::InvalidArgument
        );
    }
}
