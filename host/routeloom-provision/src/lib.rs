//! RouteLoom provisioning tooling core — the HOST side of the credential
//! lifecycle in `docs/design/sdk-completion/04-provisioning-lifecycle.md`
//! (§4.4 manufactured NVS image path P-A1, §4.3.3 RTM1 manifest signing,
//! §4.12 golden vectors). The device record format is the contract: every
//! encoder here is a byte-for-byte mirror of the portable-core codecs in
//! `components/routeloom/src/{trust_store,device_credential,trust_manifest}.cpp`,
//! and `verify` mirrors the §4.5.1 acceptance pipeline (minus the physical
//! commit) so an operator can check a manifest offline the same way a
//! device would.
//!
//! Custody honesty (§4.4 step 1, §4.10): the file-backed [`signer`] is a
//! DEVELOPMENT path — a plaintext P-256 key file guarded by POSIX
//! permissions is not production custody. Production custody is an offline
//! machine or HSM behind the same [`RootSigner`] seam; the trait is the
//! boundary, the HSM adapter is deliberately not implemented here.
//!
//! Modules:
//! - [`image`] — `RLT1` trust-store image codec + semantic validation.
//! - [`credential`] — `RLC1` device credential codec, kid derivation, grant
//!   field-consistency parse, the §4.8 epoch-window helper.
//! - [`manifest`] — `RTM1` COSE envelope, AAD/Sig_structure, assemble, and
//!   the offline acceptance check.
//! - [`signer`] — `RootSigner` seam, the dev `FileRootSigner`, keypair
//!   generation and P-256 helpers.
//! - [`nvs`] — the manufactured `rltrust`/`rlcred`/`rlboot` blob set.
//! - [`cbor`], [`crc32`], [`sha256`] — shared byte primitives mirroring the
//!   device's restricted canonical-CBOR helpers, `crc32_iso_hdlc` and
//!   `Sha256`.

pub mod cbor;
pub mod crc32;
pub mod credential;
pub mod image;
pub mod manifest;
pub mod nvs;
pub mod sha256;
pub mod signer;
pub mod verify;

/// Mirror of `components/routeloom/include/routeloom/types.hpp`.
pub const INVALID_NODE_ID: u64 = 0;
/// Broadcast/unassigned sentinel — never a valid credential or key id.
pub const BROADCAST_NODE_ID: u64 = u64::MAX;

/// Error surface for the provisioning core. Codes mirror the device's
/// `StatusCode` vocabulary so a verdict means the same thing on both sides
/// of the boundary; `detail` is a static string like the device Status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Code {
    InvalidArgument,
    InvalidState,
    Unsupported,
    NoCapacity,
    Conflict,
    RecoveryRequired,
    IntegrityError,
    ProtocolError,
    AuthorizationFailed,
    InternalError,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub code: Code,
    pub detail: &'static str,
}

impl Error {
    pub const fn new(code: Code, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn err<T>(code: Code, detail: &'static str) -> Result<T> {
    Err(Error::new(code, detail))
}
