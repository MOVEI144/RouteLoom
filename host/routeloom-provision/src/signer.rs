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
fn fill_random(out: &mut [u8]) -> Result<()> {
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
        format!(
            "{{\n  \"format\": \"{ROOT_KEY_FORMAT}\",\n  \"custody\": \"development-file\",\n  \"root_id\": \"{:016x}\",\n  \"secret_hex\": \"{}\",\n  \"pubkey_hex\": \"{}\"\n}}\n",
            self.root_id,
            hex_encode(&self.signing_key.to_bytes()),
            hex_encode(&self.pubkey),
        )
    }

    /// Write the key file with mode 0600, refusing to overwrite an existing
    /// file — clobbering a root key silently is worse than making the
    /// operator delete it deliberately.
    pub fn save(&self, path: &Path) -> Result<()> {
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
            .map_err(|_| Error::new(Code::Io, "root key create (exists? refusing to overwrite)"))?;
        file.write_all(self.to_json().as_bytes())
            .map_err(|_| Error::new(Code::Io, "root key write"))?;
        Self::enforce_private_perms(path)
    }

    /// Refuse to hand out a key whose file is group/other-accessible —
    /// POSIX permissions are the only custody this path has (§4.10).
    #[cfg(unix)]
    fn enforce_private_perms(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|_| Error::new(Code::Io, "root key stat"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return err(
                Code::AuthorizationFailed,
                "root key file is group/other-accessible (chmod 0600 required)",
            );
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn enforce_private_perms(_path: &Path) -> Result<()> {
        Ok(())
    }

    /// Load a dev root key: parse the JSON document, enforce 0600, and
    /// recompute the pubkey from the secret — a file whose halves disagree
    /// is corruption, never a cue to pick one.
    pub fn load(path: &Path) -> Result<Self> {
        Self::enforce_private_perms(path)?;
        let text =
            std::fs::read_to_string(path).map_err(|_| Error::new(Code::Io, "root key read"))?;
        let doc = routeloom_json::parse(&text)
            .map_err(|_| Error::new(Code::ProtocolError, "root key json"))?;
        if doc.get("format").and_then(|f| f.as_str()) != Some(ROOT_KEY_FORMAT) {
            return err(Code::ProtocolError, "root key format");
        }
        let root_id = doc
            .get("root_id")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or(Error::new(Code::ProtocolError, "root key root_id"))?;
        let secret = doc
            .get("secret_hex")
            .and_then(|v| v.as_str())
            .and_then(|s| hex_decode_exact(s, 32))
            .ok_or(Error::new(Code::ProtocolError, "root key secret"))?;
        let claimed_pub = doc
            .get("pubkey_hex")
            .and_then(|v| v.as_str())
            .and_then(|s| hex_decode_exact(s, 64))
            .ok_or(Error::new(Code::ProtocolError, "root key pubkey"))?;
        let mut secret_arr = [0_u8; 32];
        secret_arr.copy_from_slice(&secret);
        let signer = Self::from_secret(root_id, &secret_arr)?;
        let mut claimed = [0_u8; 64];
        claimed.copy_from_slice(&claimed_pub);
        if signer.pubkey != claimed {
            return err(Code::IntegrityError, "root key pair inconsistent");
        }
        Ok(signer)
    }
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
        let signature: Signature = self.signing_key.sign(sig_structure);
        let signature = signature.normalize_s().unwrap_or(signature);
        let bytes = signature.to_bytes();
        let mut out = [0_u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
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
}
