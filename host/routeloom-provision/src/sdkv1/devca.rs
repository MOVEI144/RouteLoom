//! Device CA custody seam and DevCert issuing (docs/design/sdk-v1/07 §6,
//! 08 P7-1). The Device CA signs the office-issued DevCert that binds a
//! NodeId to the device's P-256 key (02 §3); the Site Authority verifies it
//! at join time (02 §8). It never signs anything else.
//!
//! [`DeviceCaSigner`] is the same boundary as [`RootSigner`]: the trait is
//! the custody line, the production implementation (HSM / offline signing
//! station) is deliberately not here. [`FileDeviceCaSigner`] is the
//! DEVELOPMENT path — a plaintext key document guarded by POSIX 0600, like
//! `FileRootSigner`, and never production custody.
//!
//! A DevCert is issued only for a key whose possession was proven
//! ([`VerifiedDeviceKey`], produced solely by `pop::pop_verify`) — V1-H09
//! "no DevCert for a public key without proof of possession".

use std::path::Path;

use crate::signer::{
    generate_keypair, key_document_json, read_key_document, write_private_file, FileRootSigner,
    RootSigner,
};
use crate::{err, Code, Result};

use super::cert::{cert_issue, cert_verify, CertClaims, CertType};
use super::id_valid;
use super::pop::VerifiedDeviceKey;

/// The dev Device CA key document marker.
pub const DEVICE_CA_KEY_FORMAT: &str = "routeloom-device-ca-key-v1";

/// Printed whenever a file-backed Device CA key is used.
pub const DEVICE_CA_CUSTODY_WARNING: &str = "warning: development Device CA custody — a plaintext P-256 key file guarded only by POSIX 0600 permissions is NOT production custody; the production Device CA lives on the office signing station/HSM behind the DeviceCaSigner seam (sdk-v1/07 SS6). Anyone holding this file can mint DevCerts for any NodeId";

/// Who signs DevCerts (07 §6 "`DeviceCaSigner` trait, the same boundary as
/// `RootSigner`"). `sign` receives the COSE Sig_structure bytes and returns
/// raw `R || S`, low-S; the id is the DevCert `iss` claim.
pub trait DeviceCaSigner {
    /// Administrative Device CA id (DevCert `iss`, never a key hash).
    fn device_ca_id(&self) -> u64;
    /// X || Y public half — what the Site Authority is configured with.
    fn pubkey(&self) -> [u8; 64];
    /// ECDSA P-256/SHA-256 over the Sig_structure bytes → R || S, low-S.
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]>;
}

/// Adapts a Device CA to the certificate issuer seam without letting a
/// root/SAK signer stand in for it.
struct IssuerAdapter<'a>(&'a dyn DeviceCaSigner);

impl RootSigner for IssuerAdapter<'_> {
    fn root_id(&self) -> u64 {
        self.0.device_ca_id()
    }
    fn pubkey(&self) -> [u8; 64] {
        self.0.pubkey()
    }
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]> {
        self.0.sign(sig_structure)
    }
}

/// Development file-backed Device CA (`routeloom-device-ca-key-v1`).
pub struct FileDeviceCaSigner {
    inner: FileRootSigner,
}

impl FileDeviceCaSigner {
    /// From explicit key material (tests, golden vectors). The id must be a
    /// valid DevCert issuer (not 0, not all-ones).
    pub fn from_secret(device_ca_id: u64, secret: &[u8; 32]) -> Result<Self> {
        if !id_valid(device_ca_id) {
            return err(Code::InvalidArgument, "device ca id");
        }
        Ok(Self {
            inner: FileRootSigner::from_secret(device_ca_id, secret)?,
        })
    }

    /// A fresh Device CA pair from the OS CSPRNG.
    pub fn generate(device_ca_id: u64) -> Result<Self> {
        let (secret, _) = generate_keypair()?;
        Self::from_secret(device_ca_id, &secret)
    }

    /// The key document (contains the secret scalar).
    pub fn to_json(&self) -> String {
        key_document_json(
            DEVICE_CA_KEY_FORMAT,
            "device_ca_id",
            self.inner.root_id(),
            &self.inner.secret_scalar(),
            &self.inner.pubkey(),
        )
    }

    /// Write the key document with mode 0600, never overwriting.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_private_file(path, self.to_json().as_bytes())
    }

    /// Load a key document: 0600 enforced, format checked, public half
    /// recomputed from the secret (a disagreeing file is corruption).
    pub fn load(path: &Path) -> Result<Self> {
        let (id, secret) = read_key_document(path, DEVICE_CA_KEY_FORMAT, "device_ca_id")?;
        Self::from_secret(id, &secret)
    }
}

impl DeviceCaSigner for FileDeviceCaSigner {
    fn device_ca_id(&self) -> u64 {
        self.inner.root_id()
    }
    fn pubkey(&self) -> [u8; 64] {
        self.inner.pubkey()
    }
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]> {
        self.inner.sign(sig_structure)
    }
}

/// Product fields the office assigns to a DevCert (02 §3 private claim
/// `[1, model, hw_rev, serial]`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DevCertProfile {
    pub model: u16,
    pub hw_rev: u8,
    pub serial: u32,
}

/// Issue the DevCert for a possession-proven device key. The certificate
/// is verified under the signer's public half before it is returned, so a
/// misbehaving custody backend (wrong key, broken signature) can never
/// produce a DevCert the Site Authority would later reject.
pub fn devcert_issue(
    signer: &dyn DeviceCaSigner,
    device: &VerifiedDeviceKey,
    profile: &DevCertProfile,
) -> Result<Vec<u8>> {
    let claims = CertClaims {
        cert_type: CertType::Device,
        issuer: signer.device_ca_id(),
        subject: device.node_id(),
        pubkey: device.pubkey(),
        model: profile.model,
        hw_rev: profile.hw_rev,
        serial: profile.serial,
        ..CertClaims::default()
    };
    let cert = cert_issue(&claims, &IssuerAdapter(signer))?;
    let (decoded, verified) = cert_verify(&cert, &signer.pubkey())?;
    if !verified || decoded != claims {
        return err(
            Code::InternalError,
            "device ca signer produced an invalid devcert",
        );
    }
    Ok(cert)
}

/// Site Authority side of 02 §8 VERIFY (the DevCert half): decode, check the
/// type and issuer, verify under the Device CA key. Returns the claims.
pub fn devcert_verify(
    cert: &[u8],
    device_ca_id: u64,
    device_ca_pubkey: &[u8; 64],
) -> Result<CertClaims> {
    let (claims, verified) = cert_verify(cert, device_ca_pubkey)?;
    if claims.cert_type != CertType::Device || claims.issuer != device_ca_id {
        return err(Code::AuthorizationFailed, "not a devcert of this device ca");
    }
    if !verified {
        return err(Code::AuthorizationFailed, "devcert signature");
    }
    Ok(claims)
}
