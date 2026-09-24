//! Site CA custody seam and SiteCert issuing (docs/design/sdk-v1/07 §6,
//! 08 P7-2). The Site CA signs the SiteCert that binds a site_id to the
//! site's SAK (02 §3); the device anchors it at its RLI1 Site CA anchor
//! (02 §10.1) and the Site Authority checks it at start. It never signs
//! anything else.
//!
//! [`SiteCaSigner`] is the same boundary as `DeviceCaSigner`: the trait
//! is the custody line, the production implementation (HQ signing station
//! / HSM, used when the site PC is set up) is deliberately not here.
//! [`FileSiteCaSigner`] is the DEVELOPMENT path — a plaintext key document
//! guarded by POSIX 0600, like `FileDeviceCaSigner`, and never production
//! custody.
//!
//! The SAK public half arrives out of band (copied from the site PC that
//! generated it); a SiteCert for the wrong key is useless rather than
//! dangerous — the Site Authority refuses to start unless the SAK it holds
//! matches the SiteCert's cnf key and site_id.

use std::path::Path;

use crate::signer::{
    generate_keypair, key_document_json, read_key_document, write_private_file, FileRootSigner,
    RootSigner,
};
use crate::{err, Code, Result};

use super::cert::{cert_issue, cert_verify, CertClaims, CertType, SITE_USAGE_AUTHORITY};
use super::id_valid;

/// The dev Site CA key document marker.
pub const SITE_CA_KEY_FORMAT: &str = "routeloom-site-ca-key-v1";

/// Printed whenever a file-backed Site CA key is used.
pub const SITE_CA_CUSTODY_WARNING: &str = "warning: development Site CA custody — a plaintext P-256 key file guarded only by POSIX 0600 permissions is NOT production custody; the production Site CA lives on the HQ signing station/HSM behind the SiteCaSigner seam (sdk-v1/07 §6). Anyone holding this file can mint SiteCerts for any site";

/// Who signs SiteCerts (07 §6 "`site-cert` command": the Site CA issues).
/// `sign` receives the COSE Sig_structure bytes and returns raw `R || S`,
/// low-S; the id is the SiteCert `iss` claim.
pub trait SiteCaSigner {
    /// Administrative Site CA id (SiteCert `iss`, never a key hash).
    fn site_ca_id(&self) -> u64;
    /// X || Y public half — what devices carry as their Site CA anchor and
    /// what the Site Authority is configured with.
    fn pubkey(&self) -> [u8; 64];
    /// ECDSA P-256/SHA-256 over the Sig_structure bytes → R || S, low-S.
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]>;
}

/// Adapts a Site CA to the certificate issuer seam without letting a
/// root/Device CA signer stand in for it.
struct IssuerAdapter<'a>(&'a dyn SiteCaSigner);

impl RootSigner for IssuerAdapter<'_> {
    fn root_id(&self) -> u64 {
        self.0.site_ca_id()
    }
    fn pubkey(&self) -> [u8; 64] {
        self.0.pubkey()
    }
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]> {
        self.0.sign(sig_structure)
    }
}

/// Development file-backed Site CA (`routeloom-site-ca-key-v1`).
pub struct FileSiteCaSigner {
    inner: FileRootSigner,
}

impl FileSiteCaSigner {
    /// From explicit key material (tests, golden vectors). The id must be a
    /// valid SiteCert issuer (not 0, not all-ones).
    pub fn from_secret(site_ca_id: u64, secret: &[u8; 32]) -> Result<Self> {
        if !id_valid(site_ca_id) {
            return err(Code::InvalidArgument, "site ca id");
        }
        Ok(Self {
            inner: FileRootSigner::from_secret(site_ca_id, secret)?,
        })
    }

    /// A fresh Site CA pair from the OS CSPRNG.
    pub fn generate(site_ca_id: u64) -> Result<Self> {
        let (secret, _) = generate_keypair()?;
        Self::from_secret(site_ca_id, &secret)
    }

    /// The key document (contains the secret scalar).
    pub fn to_json(&self) -> String {
        key_document_json(
            SITE_CA_KEY_FORMAT,
            "site_ca_id",
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
        let (id, secret) = read_key_document(path, SITE_CA_KEY_FORMAT, "site_ca_id")?;
        Self::from_secret(id, &secret)
    }
}

impl SiteCaSigner for FileSiteCaSigner {
    fn site_ca_id(&self) -> u64 {
        self.inner.root_id()
    }
    fn pubkey(&self) -> [u8; 64] {
        self.inner.pubkey()
    }
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; 64]> {
        self.inner.sign(sig_structure)
    }
}

/// Site fields the HQ assigns to a SiteCert (02 §3 private claim
/// `[2, network_low32, site_epoch, usage, serial]`). `usage` is always the
/// Site Authority bit — the only usage bit v1 defines.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SiteCertProfile {
    pub network_low32: u32,
    pub site_epoch: u32,
    pub serial: u32,
}

/// Issue the SiteCert binding `site_id` to `sak_pubkey`. The certificate
/// is verified under the signer's public half before it is returned, so a
/// misbehaving custody backend (wrong key, broken signature) can never
/// produce a SiteCert the Site Authority would later reject.
pub fn sitecert_issue(
    signer: &dyn SiteCaSigner,
    site_id: u64,
    sak_pubkey: &[u8; 64],
    profile: &SiteCertProfile,
) -> Result<Vec<u8>> {
    let claims = CertClaims {
        cert_type: CertType::Site,
        issuer: signer.site_ca_id(),
        subject: site_id,
        pubkey: *sak_pubkey,
        network_low32: profile.network_low32,
        site_epoch: profile.site_epoch,
        usage: SITE_USAGE_AUTHORITY,
        serial: profile.serial,
        ..CertClaims::default()
    };
    let cert = cert_issue(&claims, &IssuerAdapter(signer))?;
    let (decoded, verified) = cert_verify(&cert, &signer.pubkey())?;
    if !verified || decoded != claims {
        return err(
            Code::InternalError,
            "site ca signer produced an invalid sitecert",
        );
    }
    Ok(cert)
}

/// Site Authority side of the start-up check: decode, check the type and
/// issuer, verify under the Site CA key. Returns the claims.
pub fn sitecert_verify(
    cert: &[u8],
    site_ca_id: u64,
    site_ca_pubkey: &[u8; 64],
) -> Result<CertClaims> {
    let (claims, verified) = cert_verify(cert, site_ca_pubkey)?;
    if claims.cert_type != CertType::Site || claims.issuer != site_ca_id {
        return err(Code::AuthorizationFailed, "not a sitecert of this site ca");
    }
    if !verified {
        return err(Code::AuthorizationFailed, "sitecert signature");
    }
    Ok(claims)
}
