//! Cipher suite 2 primitives (RFC 9528 §3.6, §10.2): SHA-256, HKDF,
//! EDHOC_KDF, P-256 ECDH with x-only public keys, ES256, AES-CCM-16-64-128.

use aes::Aes128;
use ccm::aead::{AeadInPlace, KeyInit};
use ccm::consts::{U13, U8};
use hkdf::Hkdf;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::cbor;
use crate::{Error, Result};

pub const HASH_LEN: usize = 32;
pub const AEAD_KEY_LEN: usize = 16;
pub const AEAD_NONCE_LEN: usize = 13;
pub const AEAD_TAG_LEN: usize = 8;
/// "EDHOC MAC length" of suite 2 — MAC_2/MAC_3 size for static-DH
/// authentication (methods 1..3). Signature authentication uses HASH_LEN.
pub const EDHOC_MAC_LEN: usize = 8;
pub const COORD_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

type Aes128Ccm = ccm::Ccm<Aes128, U8, U13>;

pub fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(data).into()
}

/// HKDF-Extract(salt, IKM) (RFC 9528 §4.1.1.1 for suite 2).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// EDHOC_KDF(PRK, label, context, length) = HKDF-Expand(PRK, info, length)
/// with `info = (label: uint, context: bstr, length: uint)` (§4.1.2).
pub fn edhoc_kdf(
    prk: &[u8; HASH_LEN],
    label: u64,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let mut info = Vec::with_capacity(context.len() + 16);
    cbor::write_head(&mut info, 0, label);
    cbor::write_bstr(&mut info, context);
    cbor::write_head(&mut info, 0, length as u64);
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::Crypto("prk length"))?;
    let mut out = vec![0_u8; length];
    hkdf.expand(&info, &mut out)
        .map_err(|_| Error::Crypto("hkdf expand length"))?;
    Ok(out)
}

pub(crate) fn kdf32(prk: &[u8; HASH_LEN], label: u64, context: &[u8]) -> Result<[u8; HASH_LEN]> {
    let bytes = edhoc_kdf(prk, label, context, HASH_LEN)?;
    let mut out = [0_u8; HASH_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn secret_key(scalar: &[u8; 32]) -> Result<SecretKey> {
    SecretKey::from_slice(scalar).map_err(|_| Error::Crypto("private scalar out of range"))
}

/// X || Y of `scalar`·G.
pub fn public_key_xy(scalar: &[u8; 32]) -> Result<[u8; 64]> {
    let point = secret_key(scalar)?.public_key().to_encoded_point(false);
    let mut out = [0_u8; 64];
    out.copy_from_slice(&point.as_bytes()[1..]);
    Ok(out)
}

/// The x-only wire form of an ephemeral public key (G_X / G_Y, §3.7).
pub fn public_key_x(scalar: &[u8; 32]) -> Result<[u8; COORD_LEN]> {
    let xy = public_key_xy(scalar)?;
    let mut out = [0_u8; COORD_LEN];
    out.copy_from_slice(&xy[..COORD_LEN]);
    Ok(out)
}

/// A peer's x-only key as a curve point. Either y root gives the same ECDH
/// x-coordinate, so the even root is taken (as libedhoc's backend does);
/// an x that is not a field element or has no point is refused.
fn peer_point_from_x(x: &[u8]) -> Result<PublicKey> {
    if x.len() != COORD_LEN {
        return Err(Error::Decode("ephemeral key length"));
    }
    let mut sec1 = [0_u8; 1 + COORD_LEN];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(x);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::Crypto("ephemeral key not on P-256"))
}

fn peer_point_from_xy(xy: &[u8; 64]) -> Result<PublicKey> {
    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(xy);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::Crypto("public key not on P-256"))
}

/// Validates an x-only key without using it.
pub fn check_x(x: &[u8]) -> Result<()> {
    peer_point_from_x(x).map(|_| ())
}

fn ecdh(scalar: &[u8; 32], peer: &PublicKey) -> Result<[u8; 32]> {
    let secret = secret_key(scalar)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let mut out = [0_u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

/// ECDH with a peer ephemeral key in x-only form (G_XY).
pub fn ecdh_x(scalar: &[u8; 32], peer_x: &[u8]) -> Result<[u8; 32]> {
    ecdh(scalar, &peer_point_from_x(peer_x)?)
}

/// ECDH with a peer static key X || Y (G_RX / G_IY, methods 1..3).
pub fn ecdh_xy(scalar: &[u8; 32], peer_xy: &[u8; 64]) -> Result<[u8; 32]> {
    ecdh(scalar, &peer_point_from_xy(peer_xy)?)
}

/// ES256 over `message` (SHA-256 inside), RFC 6979 deterministic.
pub fn es256_sign(scalar: &[u8; 32], message: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
    let key = SigningKey::from_bytes(scalar.into()).map_err(|_| Error::Crypto("signing key"))?;
    let signature: Signature = key.sign(message);
    let mut out = [0_u8; SIGNATURE_LEN];
    out.copy_from_slice(&signature.to_bytes());
    Ok(out)
}

/// ES256 verification. Both S halves are accepted — RFC 9528 does not ask
/// for low-S and the device backend (micro-ecc) does not normalise.
pub fn es256_verify(public_xy: &[u8; 64], message: &[u8], signature: &[u8]) -> bool {
    let Ok(point) = peer_point_from_xy(public_xy) else {
        return false;
    };
    let key = VerifyingKey::from(point);
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// AES-CCM-16-64-128 seal: ciphertext || tag.
pub fn aead_seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes128Ccm::new(&(*key).into());
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&(*nonce).into(), aad, &mut buffer)
        .map_err(|_| Error::Crypto("aead seal"))?;
    buffer.extend_from_slice(&tag);
    Ok(buffer)
}

/// AES-CCM-16-64-128 open of ciphertext || tag; a bad tag is an
/// authentication failure and no plaintext is returned.
pub fn aead_open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    if sealed.len() < AEAD_TAG_LEN {
        return Err(Error::Decode("ciphertext shorter than the tag"));
    }
    let (body, tag) = sealed.split_at(sealed.len() - AEAD_TAG_LEN);
    let mut tag_bytes = [0_u8; AEAD_TAG_LEN];
    tag_bytes.copy_from_slice(tag);
    let cipher = Aes128Ccm::new(&(*key).into());
    let mut buffer = body.to_vec();
    cipher
        .decrypt_in_place_detached(&(*nonce).into(), aad, &mut buffer, &tag_bytes.into())
        .map_err(|_| Error::Authentication("aead tag"))?;
    Ok(buffer)
}

/// Reads a fresh P-256 scalar from the OS CSPRNG (/dev/urandom), retrying
/// the ~2^-32 out-of-range draws.
pub fn random_scalar() -> Result<[u8; 32]> {
    use std::io::Read;
    let mut file =
        std::fs::File::open("/dev/urandom").map_err(|_| Error::Crypto("open /dev/urandom"))?;
    for _ in 0..16 {
        let mut scalar = [0_u8; 32];
        file.read_exact(&mut scalar)
            .map_err(|_| Error::Crypto("read /dev/urandom"))?;
        if SecretKey::from_slice(&scalar).is_ok() {
            return Ok(scalar);
        }
    }
    Err(Error::Crypto("no valid scalar drawn"))
}
