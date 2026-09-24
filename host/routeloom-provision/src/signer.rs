//! The `RootSigner` seam and the development file-backed implementation
//! (04-provisioning-lifecycle.md §4.4 step 1, §4.10). The trait is the
//! custody boundary: production custody is an offline machine or HSM
//! signing the same Sig_structure bytes; `FileRootSigner` is the honest
//! development path — a plaintext P-256 key file guarded by POSIX
//! permissions, which is never production custody.
//!
//! Signature profile (mirrored from `trust_manifest.cpp`/`config_cose.cpp`):
//! ECDSA P-256 over `SHA-256(Sig_structure)`, raw `R || S` (64 bytes),
//! RFC 6979 deterministic nonce, and the low-S canonicality rule — a
//! signer MUST emit `s <= (n-1)/2` or every device rejects the manifest.

use std::io::Read;
use std::path::Path;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::SecretKey;

use crate::{err, Code, Error, Result};

/// P-256 group order n (big-endian) — `kSecp256r1Order` in config_cose.cpp.
/// Bounds the R/S range check the verifier applies.
pub const SECP256R1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// (n-1)/2 — `kSecp256r1HalfOrder`; the maximum accepted S under the
/// manifest/permit low-S rule.
pub const SECP256R1_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8C, 0xF4, 0x27, 0x9D, 0xCE, 0x56, 0x17, 0xE3, 0x19, 0x5A, 0x88,
];

/// Big-endian 32-byte compare — `cose_be32_cmp`. Returns -1/0/1.
pub fn be32_cmp(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] != b[i] {
            return if a[i] < b[i] { -1 } else { 1 };
        }
    }
    0
}

/// `cose_be32_is_zero`.
pub fn be32_is_zero(v: &[u8; 32]) -> bool {
    v.iter().all(|&b| b == 0)
}

/// The R/S range + low-S canonicality rule the device's manifest/permit
/// verifiers apply before the point multiply: R and S in [1, n-1] and
/// S <= (n-1)/2. `signature` is the raw 64-byte R || S envelope field.
pub fn signature_range_check(signature: &[u8; 64]) -> Result<()> {
    let r: &[u8; 32] = signature[..32].try_into().expect("32");
    let s: &[u8; 32] = signature[32..].try_into().expect("32");
    if be32_is_zero(r)
        || be32_is_zero(s)
        || be32_cmp(r, &SECP256R1_ORDER) >= 0
        || be32_cmp(s, &SECP256R1_ORDER) >= 0
        || be32_cmp(s, &SECP256R1_HALF_ORDER) > 0
    {
        return err(Code::AuthorizationFailed, "signature range");
    }
    Ok(())
}

/// The custody statement printed every time a file-backed key is used —
/// §4.4 step 1 / §4.10, stated plainly rather than papered over.
pub const FILE_KEY_CUSTODY_WARNING: &str = "warning: development key custody — a plaintext P-256 root key file guarded only by POSIX 0600 permissions is NOT production custody; production root keys live on an offline machine/HSM behind the RootSigner seam (04-provisioning-lifecycle.md SS4.4, SS4.10)";

/// The dev root-key file format marker (JSON document).
pub const ROOT_KEY_FORMAT: &str = "routeloom-root-key-v1";
/// The dev CONFIG AUTHORITY key file format marker — distinct from the
/// root marker AND the id field (`authority_id`, not `root_id`) so a root
/// key file never loads as an authority key and vice versa. The config
/// issuer (§7.2) only ever loads this format; root custody never flows
/// into permit/recovery signing through a shared loader.
pub const AUTHORITY_KEY_FORMAT: &str = "routeloom-config-authority-key-v1";

/// Who signs a trust manifest: the tooling boundary §4.4 step 1 names.
/// `sign` takes the CBOR Sig_structure bytes (the manifest module builds
/// them); implementations return the raw 64-byte R || S signature,
/// low-S normalized — RFC 6979 determinism is what makes the golden
/// vectors reproducible.
pub trait RootSigner {
    /// The administrative 8-byte id the manifest's protected-header kid
    /// names (§4.3.1 — assigned at key creation, never a key hash).
    fn root_id(&self) -> u64;
    /// X || Y public half (64 bytes) — the anchor-table material.
    fn pubkey(&self) -> [u8; 64];
    /// ECDSA P-256/SHA-256 over the Sig_structure bytes → R || S, low-S.
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]>;
}

/// Compute the X || Y public half for a P-256 private scalar — the host
/// mirror of `uECC_compute_public_key`. Returns None for an out-of-range
/// scalar (uECC fails the same way); callers treat that as corruption.
pub fn pubkey_from_secret(secret: &[u8; 32]) -> Option<[u8; 64]> {
    let secret_key = SecretKey::from_slice(secret).ok()?;
    Some(pubkey_xy(&secret_key.public_key()))
}

/// SEC1 uncompressed-point → raw X || Y (strip the 0x04 head).
pub fn pubkey_xy(public_key: &p256::PublicKey) -> [u8; 64] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = public_key.to_encoded_point(false);
    let bytes = point.as_bytes();
    debug_assert_eq!(bytes.len(), 65);
    debug_assert_eq!(bytes[0], 0x04);
    let mut out = [0_u8; 64];
    out.copy_from_slice(&bytes[1..]);
    out
}

/// A P-256 keypair: (private scalar, public X || Y). The private half is
/// drawn from the OS RNG and rejection-sampled to the curve order by
/// `SecretKey::from_slice`; there is no weak fallback — if the OS cannot
/// supply entropy the call fails instead of inventing it.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 64])> {
    loop {
        let mut secret = [0_u8; 32];
        fill_random(&mut secret)?;
        if let Some(pubkey) = pubkey_from_secret(&secret) {
            return Ok((secret, pubkey));
        }
        // P(invalid draw) ~ 2^-32: rejected scalars are redrawn uniformly,
        // which keeps the distribution unbiased over [1, n-1].
    }
}

/// Fill `out` from /dev/urandom — the host's CSPRNG. Any read failure is
/// an error, never a downgrade to time/pid material.
pub fn fill_random(out: &mut [u8]) -> Result<()> {
    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|_| Error::new(Code::Io, "open /dev/urandom"))?;
    file.read_exact(out)
        .map_err(|_| Error::new(Code::Io, "read /dev/urandom"))
}

/// Fixed test keypair — the host mirror of `test_keypair(seed)` in
/// `tests/cpp/test_provisioning.hpp`: the private scalar is the seed byte
/// repeated 32×, the public half derived on-curve. The same seeds
/// (0x11/0x22/0x33/…) produce the same pubkeys the C++ suite fixtures
/// hold. TEST MATERIAL ONLY — never a real key.
pub fn test_keypair(seed: u8) -> ([u8; 32], [u8; 64]) {
    let secret = [seed; 32];
    let pubkey = pubkey_from_secret(&secret)
        .unwrap_or_else(|| panic!("test seed 0x{seed:02x} is not a valid P-256 scalar"));
    (secret, pubkey)
}

/// Development file-backed root signer. The JSON document carries the
/// administrative root_id, the secret scalar and the public half so the
/// loader can verify file integrity by recomputation — a file whose
/// secret does not reproduce its pubkey is corrupt, not a different key.
pub struct FileRootSigner {
    root_id: u64,
    signing_key: SigningKey,
    pubkey: [u8; 64],
}

impl FileRootSigner {
    /// Construct from explicit key material (tests/golden vectors).
    /// `secret` must be a valid P-256 scalar; the pubkey is derived, never
    /// trusted from the caller.
    pub fn from_secret(root_id: u64, secret: &[u8; 32]) -> Result<Self> {
        if root_id == 0 {
            return err(Code::InvalidArgument, "root id zero");
        }
        let pubkey = pubkey_from_secret(secret)
            .ok_or(Error::new(Code::InvalidArgument, "root secret range"))?;
        let signing_key = SigningKey::from_slice(secret)
            .map_err(|_| Error::new(Code::InvalidArgument, "root secret range"))?;
        Ok(Self {
            root_id,
            signing_key,
            pubkey,
        })
    }

    /// Generate a fresh dev root pair under `root_id`.
    pub fn generate(root_id: u64) -> Result<Self> {
        let (secret, _) = generate_keypair()?;
        Self::from_secret(root_id, &secret)
    }

    /// Serialize the dev key document. `secret_hex` is the private scalar —
    /// this file is a custody liability by design (see
    /// FILE_KEY_CUSTODY_WARNING).
    pub fn to_json(&self) -> String {
        key_document_json(
            ROOT_KEY_FORMAT,
            "root_id",
            self.root_id,
            &self.signing_key.to_bytes().into(),
            &self.pubkey,
        )
    }

    /// The private scalar, for key-document serialization by the other
    /// file-backed signers built on this one.
    pub(crate) fn secret_scalar(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    /// Write the key file with mode 0600, refusing to overwrite an existing
    /// file — clobbering a root key silently is worse than making the
    /// operator delete it deliberately.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_private_file(path, self.to_json().as_bytes())
    }

    /// Load a dev root key: parse the JSON document, enforce 0600, and
    /// recompute the pubkey from the secret — a file whose halves disagree
    /// is corruption, never a cue to pick one.
    pub fn load(path: &Path) -> Result<Self> {
        let (root_id, secret) = read_key_document(path, ROOT_KEY_FORMAT, "root_id")?;
        Self::from_secret(root_id, &secret)
    }
}

/// The dev key document shared by the file-backed signers (root, Device
/// CA): format marker, custody statement, administrative id, secret scalar
/// and public half.
pub(crate) fn key_document_json(
    format: &str,
    id_field: &str,
    id: u64,
    secret: &[u8; 32],
    pubkey: &[u8; 64],
) -> String {
    format!(
        "{{\n  \"format\": \"{format}\",\n  \"custody\": \"development-file\",\n  \"{id_field}\": \"{id:016x}\",\n  \"secret_hex\": \"{}\",\n  \"pubkey_hex\": \"{}\"\n}}\n",
        hex_encode(secret),
        hex_encode(pubkey),
    )
}

/// Create `path` with mode 0600 and write `bytes`, refusing to overwrite an
/// existing file. Used for key documents and for every output that carries
/// a private scalar (injected-key identity records and their NVS blobs).
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| Error::new(Code::Io, "key file create (exists? refusing to overwrite)"))?;
    file.write_all(bytes)
        .map_err(|_| Error::new(Code::Io, "key file write"))?;
    enforce_private_perms(path)
}

/// Refuse to hand out a key whose file is group/other-accessible — POSIX
/// permissions are the only custody this path has (§4.10).
#[cfg(unix)]
fn enforce_private_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|_| Error::new(Code::Io, "key file stat"))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return err(
            Code::AuthorizationFailed,
            "key file is group/other-accessible (chmod 0600 required)",
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_perms(_path: &Path) -> Result<()> {
    Ok(())
}

/// Parse a dev key document: enforce 0600, check the format marker, and
/// recompute the public half from the secret — a document whose halves
/// disagree is corruption, never a cue to pick one. Returns (id, secret).
pub(crate) fn read_key_document(
    path: &Path,
    format: &str,
    id_field: &str,
) -> Result<(u64, [u8; 32])> {
    enforce_private_perms(path)?;
    let text = std::fs::read_to_string(path).map_err(|_| Error::new(Code::Io, "key file read"))?;
    let doc = routeloom_json::parse(&text)
        .map_err(|_| Error::new(Code::ProtocolError, "key file json"))?;
    if doc.get("format").and_then(|f| f.as_str()) != Some(format) {
        return err(Code::ProtocolError, "key file format");
    }
    let id = doc
        .get(id_field)
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or(Error::new(Code::ProtocolError, "key file id"))?;
    let secret: [u8; 32] = doc
        .get("secret_hex")
        .and_then(|v| v.as_str())
        .and_then(|s| hex_decode_exact(s, 32))
        .ok_or(Error::new(Code::ProtocolError, "key file secret"))?
        .try_into()
        .expect("32 bytes");
    let claimed: [u8; 64] = doc
        .get("pubkey_hex")
        .and_then(|v| v.as_str())
        .and_then(|s| hex_decode_exact(s, 64))
        .ok_or(Error::new(Code::ProtocolError, "key file pubkey"))?
        .try_into()
        .expect("64 bytes");
    let derived = pubkey_from_secret(&secret)
        .ok_or(Error::new(Code::InvalidArgument, "key file secret range"))?;
    if derived != claimed {
        return err(Code::IntegrityError, "key file pair inconsistent");
    }
    Ok((id, secret))
}

/// RFC 6979 deterministic ECDSA over `message` (the caller hashes with
/// SHA-256 first when the profile signs a digest — `SigningKey::sign` runs
/// the same hash internally, so both spellings share this body), S
/// normalized to the low-S canonical form every device verifier requires.
/// Shared by the root and authority file signers: one signing rule, two
/// key records that never interchange.
fn ecdsa_sign_low_s(signing_key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let signature: Signature = signing_key.sign(message);
    let signature = signature.normalize_s().unwrap_or(signature);
    let bytes = signature.to_bytes();
    let mut out = [0_u8; 64];
    out.copy_from_slice(&bytes);
    out
}

/// ECDSA P-256/SHA-256 verify — the host stand-in for `uECC_verify` over
/// the already-computed Sig_structure digest. R || S raw signature, X || Y
/// public key. The config issuer self-checks every COSE envelope with this
/// before it may leave the host.
pub fn ecdsa_p256_verify(pubkey: &[u8; 64], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::VerifyingKey;

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

impl RootSigner for FileRootSigner {
    fn root_id(&self) -> u64 {
        self.root_id
    }
    fn pubkey(&self) -> [u8; 64] {
        self.pubkey
    }

    /// RFC 6979 deterministic ECDSA over SHA-256(sig_structure) — the same
    /// digest the device computes before `uECC_verify` — with S normalized
    /// to the low-S canonical form the RTM1 envelope requires.
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]> {
        Ok(ecdsa_sign_low_s(&self.signing_key, sig_structure))
    }
}

/// Development file-backed CONFIG AUTHORITY signer: the RLCP1_COSE_ESP256
/// permit/recovery issuance key. Deliberately NOT a `RootSigner` — the
/// authority id must never be readable as a root permission — with its own
/// key-document format so root and authority custody cannot cross by file
/// confusion. Same file integrity rule as the root signer: the pubkey is
/// recomputed from the secret at load.
pub struct FileAuthoritySigner {
    authority_id: u64,
    signing_key: SigningKey,
    pubkey: [u8; 64],
}

impl FileAuthoritySigner {
    /// Construct from explicit key material (tests/golden vectors).
    pub fn from_secret(authority_id: u64, secret: &[u8; 32]) -> Result<Self> {
        if authority_id == 0 {
            return err(Code::InvalidArgument, "authority id zero");
        }
        let pubkey = pubkey_from_secret(secret)
            .ok_or(Error::new(Code::InvalidArgument, "authority secret range"))?;
        let signing_key = SigningKey::from_slice(secret)
            .map_err(|_| Error::new(Code::InvalidArgument, "authority secret range"))?;
        Ok(Self {
            authority_id,
            signing_key,
            pubkey,
        })
    }

    /// Generate a fresh dev authority pair under `authority_id`.
    pub fn generate(authority_id: u64) -> Result<Self> {
        let (secret, _) = generate_keypair()?;
        Self::from_secret(authority_id, &secret)
    }

    /// Serialize the dev key document (same custody liability as root keys).
    pub fn to_json(&self) -> String {
        key_document_json(
            AUTHORITY_KEY_FORMAT,
            "authority_id",
            self.authority_id,
            &self.signing_key.to_bytes().into(),
            &self.pubkey,
        )
    }

    /// Write the key file with mode 0600, refusing to overwrite.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_private_file(path, self.to_json().as_bytes())
    }

    /// Load a dev authority key: same 0600 + recomputation rules as root
    /// keys, but only the authority document format is accepted.
    pub fn load(path: &Path) -> Result<Self> {
        let (authority_id, secret) = read_key_document(path, AUTHORITY_KEY_FORMAT, "authority_id")?;
        Self::from_secret(authority_id, &secret)
    }

    /// The administrative id the permit/recovery protected-header kid names.
    pub fn authority_id(&self) -> u64 {
        self.authority_id
    }

    /// X || Y public half (64 bytes) — the provisioned verifier material.
    pub fn pubkey(&self) -> [u8; 64] {
        self.pubkey
    }

    /// RFC 6979 deterministic ECDSA over the Sig_structure bytes, low-S —
    /// the same rule as root signing, over the permit/recovery structure.
    pub fn sign(&self, sig_structure: &[u8]) -> [u8; 64] {
        ecdsa_sign_low_s(&self.signing_key, sig_structure)
    }
}

/// Lowercase hex — the workspace's one-line encoder (same shape as the
/// golden generators use).
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Strict lowercase-or-uppercase hex decode of exactly `len` bytes.
pub fn hex_decode_exact(text: &str, len: usize) -> Option<Vec<u8>> {
    if text.len() != len * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        (0..len)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hexdigit"))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_is_on_curve_and_stable() {
        for seed in [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xEE] {
            let (_, pubkey) = test_keypair(seed);
            assert!(crate::image::pubkey_on_curve(&pubkey));
        }
        assert_eq!(test_keypair(0x11).1, test_keypair(0x11).1);
        assert_ne!(test_keypair(0x11).1, test_keypair(0x22).1);
    }

    #[test]
    fn sign_is_deterministic_low_s_and_verifies() {
        let (secret, pubkey) = test_keypair(0x11);
        let signer = FileRootSigner::from_secret(0x100, &secret).unwrap();
        let a = signer.sign(b"sig-structure").unwrap();
        let b = signer.sign(b"sig-structure").unwrap();
        assert_eq!(a, b); // RFC 6979
        signature_range_check(&a).unwrap();

        // Verify against the public half through the same path verify.rs uses.
        let mut sec1 = [0_u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(&pubkey);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        use p256::ecdsa::signature::Verifier;
        let sig = Signature::from_slice(&a).unwrap();
        assert!(vk.verify(b"sig-structure", &sig).is_ok());
        assert!(vk.verify(b"other", &sig).is_err());
    }

    #[test]
    fn key_file_roundtrip_and_consistency() {
        let dir =
            std::env::temp_dir().join(format!("rl-prov-test-{}-{}", std::process::id(), "key"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("root.key");
        let (secret, _) = test_keypair(0x11);
        let signer = FileRootSigner::from_secret(0x100, &secret).unwrap();
        signer.save(&path).unwrap();
        let loaded = FileRootSigner::load(&path).unwrap();
        assert_eq!(loaded.root_id(), 0x100);
        assert_eq!(loaded.pubkey(), signer.pubkey());
        assert_eq!(loaded.sign(b"x").unwrap(), signer.sign(b"x").unwrap());
        // Refuse to overwrite an existing key file.
        assert!(signer.save(&path).is_err());
        // A file whose halves disagree is corruption.
        let text = signer
            .to_json()
            .replace(&hex_encode(&signer.pubkey())[..4], "dead");
        let bad = dir.join("bad.key");
        std::fs::write(&bad, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = FileRootSigner::load(&bad).err().expect("must fail");
        assert!(
            err.code == Code::IntegrityError || err.code == Code::ProtocolError,
            "unexpected {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn authority_key_never_loads_a_root_document() {
        let dir =
            std::env::temp_dir().join(format!("rl-prov-test-{}-{}", std::process::id(), "authkey"));
        std::fs::create_dir_all(&dir).unwrap();
        let (secret, _) = test_keypair(0x33);
        let root = FileRootSigner::from_secret(0x100, &secret).unwrap();
        let root_path = dir.join("root.key");
        root.save(&root_path).unwrap();
        // Same key material, wrong document: the authority loader refuses.
        assert!(FileAuthoritySigner::load(&root_path).is_err());
        let auth = FileAuthoritySigner::from_secret(0x42, &secret).unwrap();
        let auth_path = dir.join("auth.key");
        auth.save(&auth_path).unwrap();
        // And the reverse: a root loader refuses the authority document.
        assert!(FileRootSigner::load(&auth_path).is_err());
        let loaded = FileAuthoritySigner::load(&auth_path).unwrap();
        assert_eq!(loaded.authority_id(), 0x42);
        assert_eq!(loaded.pubkey(), auth.pubkey());
        // Same deterministic low-S rule as root signing, over the same
        // bytes — the key records differ, the signature rule does not.
        assert_eq!(
            loaded.sign(b"sig-structure"),
            root.sign(b"sig-structure").unwrap()
        );
        // The shared verifier accepts the authority signature over the
        // digest both sides compute.
        let digest = crate::sha256::sha256(b"sig-structure");
        assert!(ecdsa_p256_verify(
            &loaded.pubkey(),
            &digest,
            &loaded.sign(b"sig-structure")
        ));
        assert!(!ecdsa_p256_verify(
            &loaded.pubkey(),
            &crate::sha256::sha256(b"other"),
            &loaded.sign(b"sig-structure")
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
