//! Device-key proof of possession (docs/design/sdk-v1/07 §6 steps 2-3,
//! 08 P7-1, acceptance V1-H09 "no DevCert for a public key without proof
//! of possession").
//!
//! The office issues a fresh 32-byte challenge; the device (maintenance
//! verb, after on-device key generation with entropy READY) answers with a
//! restricted ES256 COSE_Sign1 signed by the key it wants certified:
//!
//! ```text
//! d2 84 43 a1 01 26 a0 58 6c <payload 108 B> 58 40 <R || S>      (183 B)
//! payload:
//!   0 u8  version = 1
//!   1 u8  key_location (RLC1 values: 1 nvs-plaintext, 2 efuse-ds-bound,
//!         3 secure-element; 0 is refused — no key, nothing to prove)
//!   2 u16 reserved = 0
//!   4 u64 node_id
//!  12 32B challenge (office nonce, echoed)
//!  44 64B pubkey X || Y (the key being certified; it also verifies this)
//! external AAD = "RouteLoom/device-key-pop/v1" 00   (28 B)
//! ```
//!
//! Same COSE profile as RLCW1/RRS1 (tag 18, `{1:-7}`, empty unprotected
//! map, low-S only). The domain-separated AAD keeps a PoP signature from
//! ever being a certificate, revocation-set or EDHOC signature (those have
//! an empty/other AAD or a different protected header), and the echoed
//! challenge makes a captured PoP useless for any later request.

use crate::credential::KeyLocation;
use crate::image::pubkey_on_curve;
use crate::signer::{fill_random, FileRootSigner, RootSigner};
use crate::{err, Code, Result};

use super::{cose_es256_assemble, cose_es256_parse, cose_es256_sign, cose_es256_verify, id_valid};

pub const POP_VERSION: u8 = 1;
pub const POP_CHALLENGE_SIZE: usize = 32;
pub const POP_PAYLOAD_SIZE: usize = 108;
pub const POP_OBJECT_SIZE: usize = 183;
pub const POP_DOMAIN: &str = "RouteLoom/device-key-pop/v1";

/// A device public key whose possession was proven for `node_id`. Only
/// [`pop_verify`] constructs one, so every DevCert issue path goes through
/// a verified proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDeviceKey {
    node_id: u64,
    pubkey: [u8; 64],
    key_location: KeyLocation,
}

impl VerifiedDeviceKey {
    pub fn node_id(&self) -> u64 {
        self.node_id
    }
    pub fn pubkey(&self) -> [u8; 64] {
        self.pubkey
    }
    pub fn key_location(&self) -> KeyLocation {
        self.key_location
    }
}

/// `"RouteLoom/device-key-pop/v1" 00`.
pub fn pop_aad() -> Vec<u8> {
    let mut aad = POP_DOMAIN.as_bytes().to_vec();
    aad.push(0);
    aad
}

/// A fresh office challenge from the OS CSPRNG (never time/pid material).
pub fn pop_challenge() -> Result<[u8; POP_CHALLENGE_SIZE]> {
    let mut challenge = [0_u8; POP_CHALLENGE_SIZE];
    fill_random(&mut challenge)?;
    Ok(challenge)
}

pub fn pop_payload_encode(
    node_id: u64,
    key_location: KeyLocation,
    challenge: &[u8; POP_CHALLENGE_SIZE],
    pubkey: &[u8; 64],
) -> Result<Vec<u8>> {
    if !id_valid(node_id) {
        return err(Code::InvalidArgument, "pop node id");
    }
    if key_location == KeyLocation::None {
        return err(Code::InvalidArgument, "pop key location");
    }
    if !pubkey_on_curve(pubkey) {
        return err(Code::InvalidArgument, "pop key off curve");
    }
    let mut out = Vec::with_capacity(POP_PAYLOAD_SIZE);
    out.push(POP_VERSION);
    out.push(key_location as u8);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&node_id.to_be_bytes());
    out.extend_from_slice(challenge);
    out.extend_from_slice(pubkey);
    debug_assert_eq!(out.len(), POP_PAYLOAD_SIZE);
    Ok(out)
}

/// The device side (host mirror of the firmware maintenance verb, also the
/// injected-key path where the office itself generated the key): sign the
/// challenge with the device secret. RFC 6979, low-S.
pub fn pop_sign(
    secret: &[u8; 32],
    node_id: u64,
    key_location: KeyLocation,
    challenge: &[u8; POP_CHALLENGE_SIZE],
) -> Result<Vec<u8>> {
    // The signer id is irrelevant to the PoP (no kid in the object); the
    // node id is a convenient nonzero value.
    let signer = FileRootSigner::from_secret(node_id.max(1), secret)?;
    let payload = pop_payload_encode(node_id, key_location, challenge, &signer.pubkey())?;
    let signature = cose_es256_sign(&signer, &payload, &pop_aad())?;
    Ok(cose_es256_assemble(&payload, &signature))
}

/// Office side: accept a PoP only if it is well formed, names
/// `expected_node`, echoes `challenge`, and is signed by the key it
/// carries. Malformed → ProtocolError; wrong node/challenge or a bad
/// signature → AuthorizationFailed.
pub fn pop_verify(
    object: &[u8],
    expected_node: u64,
    challenge: &[u8; POP_CHALLENGE_SIZE],
) -> Result<VerifiedDeviceKey> {
    let parts = cose_es256_parse(object, POP_PAYLOAD_SIZE, POP_PAYLOAD_SIZE, POP_OBJECT_SIZE)?;
    let payload = parts.payload;
    if payload[0] != POP_VERSION || payload[2] != 0 || payload[3] != 0 {
        return err(Code::ProtocolError, "pop head");
    }
    let key_location = match KeyLocation::from_u8(payload[1]) {
        Some(KeyLocation::None) | None => return err(Code::ProtocolError, "pop key location"),
        Some(location) => location,
    };
    let node_id = u64::from_be_bytes(payload[4..12].try_into().expect("8"));
    let echoed: &[u8] = &payload[12..44];
    let pubkey: [u8; 64] = payload[44..108].try_into().expect("64");
    if !id_valid(node_id) || !pubkey_on_curve(&pubkey) {
        return err(Code::ProtocolError, "pop fields");
    }
    if node_id != expected_node {
        return err(Code::AuthorizationFailed, "pop names another node");
    }
    // Not secret, but compare in full anyway (no early exit on the nonce).
    let mismatch = echoed
        .iter()
        .zip(challenge.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
    if mismatch != 0 {
        return err(Code::AuthorizationFailed, "pop challenge mismatch");
    }
    if !cose_es256_verify(payload, &pop_aad(), &parts.signature, &pubkey) {
        return err(Code::AuthorizationFailed, "pop signature");
    }
    Ok(VerifiedDeviceKey {
        node_id,
        pubkey,
        key_location,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::test_keypair;

    const NODE: u64 = 0x00A1_0000_0000_1234;

    #[test]
    fn sign_verify_roundtrip_and_shape() {
        let (secret, pubkey) = test_keypair(0x54);
        let challenge = [0x5A_u8; 32];
        let object = pop_sign(&secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap();
        assert_eq!(object.len(), POP_OBJECT_SIZE);
        assert_eq!(
            &object[..9],
            &[0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x58, 0x6C]
        );
        assert_eq!(pop_aad().len(), 28);
        let key = pop_verify(&object, NODE, &challenge).unwrap();
        assert_eq!(key.node_id(), NODE);
        assert_eq!(key.pubkey(), pubkey);
        assert_eq!(key.key_location(), KeyLocation::NvsPlaintext);
        // RFC 6979: deterministic.
        assert_eq!(
            pop_sign(&secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap(),
            object
        );
    }

    #[test]
    fn rejections() {
        let (secret, _) = test_keypair(0x54);
        let challenge = [0x5A_u8; 32];
        let object = pop_sign(&secret, NODE, KeyLocation::NvsPlaintext, &challenge).unwrap();
        // Wrong node, stale/foreign challenge: authorization failures.
        assert_eq!(
            pop_verify(&object, NODE + 1, &challenge).unwrap_err().code,
            Code::AuthorizationFailed
        );
        let mut other = challenge;
        other[31] ^= 1;
        assert_eq!(
            pop_verify(&object, NODE, &other).unwrap_err().code,
            Code::AuthorizationFailed
        );
        // Tampered payload (pubkey swapped for another on-curve key): the
        // signature no longer verifies under the carried key.
        let (_, other_pub) = test_keypair(0x56);
        let mut swapped = object.clone();
        swapped[9 + 44..9 + 108].copy_from_slice(&other_pub);
        assert_eq!(
            pop_verify(&swapped, NODE, &challenge).unwrap_err().code,
            Code::AuthorizationFailed
        );
        // A PoP signed by a different key than the one it carries.
        let (other_secret, _) = test_keypair(0x56);
        let (_, device_pub) = test_keypair(0x54);
        let payload =
            pop_payload_encode(NODE, KeyLocation::NvsPlaintext, &challenge, &device_pub).unwrap();
        let signer = FileRootSigner::from_secret(1, &other_secret).unwrap();
        let signature = cose_es256_sign(&signer, &payload, &pop_aad()).unwrap();
        let forged = cose_es256_assemble(&payload, &signature);
        assert_eq!(
            pop_verify(&forged, NODE, &challenge).unwrap_err().code,
            Code::AuthorizationFailed
        );
        // Signed over the empty AAD (e.g. lifted from a certificate-style
        // signature): refused.
        let signer = FileRootSigner::from_secret(1, &secret).unwrap();
        let no_domain = cose_es256_sign(&signer, &payload, &[]).unwrap();
        assert_eq!(
            pop_verify(&cose_es256_assemble(&payload, &no_domain), NODE, &challenge)
                .unwrap_err()
                .code,
            Code::AuthorizationFailed
        );
        // High-S twin of a valid signature: refused (one valid encoding).
        let mut high_s = object.clone();
        let s_offset = object.len() - 32;
        let order = crate::signer::SECP256R1_ORDER;
        let mut borrow = 0_i16;
        for i in (0..32).rev() {
            let diff = i16::from(order[i]) - i16::from(object[s_offset + i]) - borrow;
            high_s[s_offset + i] = diff.rem_euclid(256) as u8;
            borrow = i16::from(diff < 0);
        }
        assert_eq!(
            pop_verify(&high_s, NODE, &challenge).unwrap_err().code,
            Code::AuthorizationFailed
        );
        // Structural: version, key location none, reserved, truncation,
        // trailing byte.
        for (offset, value) in [(9_usize, 2_u8), (10, 0), (10, 9), (11, 1)] {
            let mut bad = object.clone();
            bad[offset] = value;
            assert_eq!(
                pop_verify(&bad, NODE, &challenge).unwrap_err().code,
                Code::ProtocolError,
                "offset {offset}"
            );
        }
        assert!(pop_verify(&object[..object.len() - 1], NODE, &challenge).is_err());
        let mut trailing = object.clone();
        trailing.push(0);
        assert!(pop_verify(&trailing, NODE, &challenge).is_err());
        // The encoder refuses what the verifier refuses.
        assert!(pop_sign(&secret, NODE, KeyLocation::None, &challenge).is_err());
        assert!(pop_sign(&secret, 0, KeyLocation::NvsPlaintext, &challenge).is_err());
        assert!(pop_sign(&secret, u64::MAX, KeyLocation::NvsPlaintext, &challenge).is_err());
    }

    #[test]
    fn challenges_are_fresh() {
        assert_ne!(pop_challenge().unwrap(), pop_challenge().unwrap());
    }
}
