//! Remote-config issuer core (scope-gateway-config P5, 04-remote-config.md
//! §4.3, 05-wire-api.md §5.4–§5.6, design-51 §7). Byte-for-byte mirror of
//! the device-side envelope profiles: the `config_dev.cpp` development
//! HMAC profile (aad || canonical || tag16) and the RLCP1_COSE_ESP256
//! restricted COSE_Sign1 profile — the host builds the same RCC1/RCR2
//! canonical commands and produces the same signed objects the device
//! verifiers accept.
//!
//! EXPERIMENTAL: the dev profile is an HMAC-SHA-256 over a shared
//! development key under SecurityProfile::Development. It is never a
//! production identity and the issuer reports itself as such. The COSE
//! profile signs with a file-backed development authority key — same
//! custody caveat, asymmetric cryptography.
//!
//! What lives here is the pure issuer core: the challenge-freshness ledger,
//! the CAS/revision binding, the NO_CHANGE shortcut, the canonical ↔
//! commit ↔ sign pipeline and the profile signers. The durable outbox and
//! the SingleAuthority sequence plug in through `ConfigAuthorityLedger` —
//! this module performs no I/O itself and never claims a transport outcome
//! as a config verdict. Profile selection is explicit and never falls
//! back: a missing key or an unoffered profile refuses BEFORE any
//! sequence reservation, signature, or mesh transmission.

use std::collections::HashMap;

use routeloom_protocol::host_ops::{
    self, ConfigOpsResult, SUB_CONFIG_CHALLENGE, SUB_CONFIG_PERMIT, SUB_CONFIG_RECOVER,
    SUB_CONFIG_RECOVERY_INFO, SUB_CONFIG_STATUS, SUB_CONFIG_TRUST, SUB_CONFIG_TRUST_STATUS,
};
use routeloom_provision::manifest::{
    cose_sig_structure, manifest_assemble, manifest_protected, COSE_SIGNATURE_SIZE,
};
use routeloom_provision::signer::{ecdsa_p256_verify, signature_range_check, FileAuthoritySigner};
use routeloom_wire::endpoint::{
    config_command_encode, config_namespace_valid, config_patch_apply, config_recovery_encode,
    config_snapshot_hash_input, config_tlv_decode, control_challenge_decode, control_status_decode,
    recovery_info_decode, trust_status_decode, ConfigCommand, ConfigField, ConfigPhase,
    ConfigRecoveryIntent, ControlChallenge, ControlStatus, RecoveryInfo, TrustStatus,
    RCR2_MAX_TOTAL, RCR2_MODE_REPROVISION, RCR2_VERSION, RECOVERY_INFO_FLAG_IMPAIRED,
    RECOVERY_INFO_FLAG_SURVIVOR_KNOWN,
};

use crate::canonical::sha256;
use crate::send_store::{ConfigAuthorityLedger, IssueIdentity, IssueRefusal};
pub use crate::send_store::{
    ISSUE_KIND_PERMIT, ISSUE_KIND_RECOVERY, ISSUE_PROFILE_COSE, ISSUE_PROFILE_DEV,
};

// The dev permit envelope (mirror of config_dev.hpp):
//   permit = aad || canonical || tag
//   aad    = "RouteLoom/config-permit/v1\0" || network u64 || target u64 || ns u16
//   tag    = HMAC-SHA256(dev_key, "RouteLoom/config-permit-dev/v1\0" || aad ||
//            canonical)[..16]
pub const CONFIG_PERMIT_DOMAIN: &[u8] = b"RouteLoom/config-permit/v1\0";
pub const CONFIG_DEV_PERMIT_DOMAIN: &[u8] = b"RouteLoom/config-permit-dev/v1\0";
pub const CONFIG_PERMIT_AAD_SIZE: usize = CONFIG_PERMIT_DOMAIN.len() + 8 + 8 + 2; // 45
pub const CONFIG_DEV_PERMIT_TAG_SIZE: usize = 16;
pub const CONFIG_PERMIT_OBJECT_MAX: usize = 1024;
// The recovery lane's own domains (mirror of config.hpp/config_dev.hpp):
// object = recovery_aad || RCR2 || tag16. The AAD domain AND the MAC
// input domain differ from the permit's, so a kind-4 object can never
// verify as a kind-3 permit, nor the reverse. RCR1 is retired outright:
// no v1 domain exists on this host anymore.
pub const CONFIG_RECOVERY_DOMAIN: &[u8] = b"RouteLoom/config-recover/v2\0";
pub const CONFIG_DEV_RECOVERY_DOMAIN: &[u8] = b"RouteLoom/config-recover-dev/v2\0";
pub const CONFIG_RECOVERY_AAD_SIZE: usize = CONFIG_RECOVERY_DOMAIN.len() + 8 + 8 + 2; // 46
pub const CONFIG_DEV_RECOVERY_OBJECT_MAX: usize =
    CONFIG_RECOVERY_AAD_SIZE + RCR2_MAX_TOTAL + CONFIG_DEV_PERMIT_TAG_SIZE;
// The restricted COSE_Sign1 envelope the RLCP1_COSE_ESP256 profile signs
// (config_cose.hpp): tag 18, array(4), canonical protected {1:-9,
// 4:authority-kid}, empty unprotected map, attached RCC1/RCR2 payload,
// raw low-S R || S. Payloads above the permit ceiling never occur —
// RCC1 ≤ 688 B, RCR2 ≤ 624 B — so the shared 774 B device cap holds.
pub const CONFIG_COSE_OBJECT_MAX: usize = 774;
/// Minimum dev-permit envelope (aad || shortest RCC1 header || tag). Only the
/// host-side self-check verifier consults it — the production path signs, and
/// the device is the verifier — so it is test-only like `dev_permit_verify`.
#[cfg(test)]
pub const RCC1_HEADER_MIN: usize = 176;
#[cfg(test)]
pub const CONFIG_DEV_PERMIT_MIN: usize =
    CONFIG_PERMIT_AAD_SIZE + RCC1_HEADER_MIN + CONFIG_DEV_PERMIT_TAG_SIZE;

/// Error surface for the issuer core — kept small and honest: a caller maps
/// these onto the ConfigOpsResult/Status codes, never onto success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidArgument,
    /// Malformed permit/command bytes on the wire.
    Malformed,
    /// The requested (target, namespace) challenge is absent.
    ChallengeMissing,
    /// The challenge budget or apply window has run out.
    Expired,
    /// The issuer's own clock regressed vs the challenge receipt.
    ClockUncertain,
    /// The base snapshot does not match the challenge's active hash (CAS).
    Stale,
    /// A permit field exceeded its object bound.
    TooLarge,
    /// The requested issuance shape is not offered: an unknown profile,
    /// a profile whose key this issuer does not hold, or a target that
    /// does not accept the selected profile. Never a fallback trigger —
    /// the lane refuses BEFORE any sequence reservation or signature.
    Unsupported,
}

/// HMAC-SHA256 over the workspace's portable `sha256` (RFC 2104): no external
/// crypto dependency, identical to the device `hmac_sha256` byte-for-byte.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0_u8; BLOCK];
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&sha256(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    block.copy_from_slice(&key_block);
    for b in block.iter_mut() {
        *b ^= 0x36;
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend_from_slice(&block);
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    block.copy_from_slice(&key_block);
    for b in block.iter_mut() {
        *b ^= 0x5c;
    }
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&block);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

#[cfg(test)]
fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// aad = domain || network u64 || target u64 || config_namespace u16 (45 B).
/// The scope binding the permit's tag authenticates.
pub fn config_permit_aad(
    network: u64,
    target: u64,
    config_namespace: u16,
) -> Result<[u8; CONFIG_PERMIT_AAD_SIZE], ConfigError> {
    if !config_namespace_valid(config_namespace) {
        return Err(ConfigError::InvalidArgument);
    }
    let mut out = [0_u8; CONFIG_PERMIT_AAD_SIZE];
    out[..CONFIG_PERMIT_DOMAIN.len()].copy_from_slice(CONFIG_PERMIT_DOMAIN);
    let mut cursor = CONFIG_PERMIT_DOMAIN.len();
    out[cursor..cursor + 8].copy_from_slice(&network.to_be_bytes());
    cursor += 8;
    out[cursor..cursor + 8].copy_from_slice(&target.to_be_bytes());
    cursor += 8;
    out[cursor..cursor + 2].copy_from_slice(&config_namespace.to_be_bytes());
    Ok(out)
}

/// tag = HMAC-SHA256(dev_key, dev_domain || aad || canonical)[..16].
pub fn config_dev_permit_tag(
    dev_key: &[u8],
    aad: &[u8; CONFIG_PERMIT_AAD_SIZE],
    canonical: &[u8],
) -> Result<[u8; CONFIG_DEV_PERMIT_TAG_SIZE], ConfigError> {
    if dev_key.is_empty() || canonical.is_empty() {
        return Err(ConfigError::InvalidArgument);
    }
    let mut input =
        Vec::with_capacity(CONFIG_DEV_PERMIT_DOMAIN.len() + aad.len() + canonical.len());
    input.extend_from_slice(CONFIG_DEV_PERMIT_DOMAIN);
    input.extend_from_slice(aad);
    input.extend_from_slice(canonical);
    let mac = hmac_sha256(dev_key, &input);
    let mut tag = [0_u8; CONFIG_DEV_PERMIT_TAG_SIZE];
    tag.copy_from_slice(&mac[..CONFIG_DEV_PERMIT_TAG_SIZE]);
    Ok(tag)
}

/// Sign a canonical RCC1 command into the dev permit envelope:
/// permit = aad || canonical || tag16. Verified on the device by the
/// dev permit verifier.
pub fn dev_sign_permit(
    dev_key: &[u8],
    command: &ConfigCommand,
    canonical: &[u8],
) -> Result<Vec<u8>, ConfigError> {
    if canonical.is_empty()
        || canonical.len() + CONFIG_PERMIT_AAD_SIZE + CONFIG_DEV_PERMIT_TAG_SIZE
            > CONFIG_PERMIT_OBJECT_MAX
    {
        return Err(ConfigError::TooLarge);
    }
    let aad = config_permit_aad(command.network, command.target, command.config_namespace)?;
    let tag = config_dev_permit_tag(dev_key, &aad, canonical)?;
    let mut permit =
        Vec::with_capacity(CONFIG_PERMIT_AAD_SIZE + canonical.len() + CONFIG_DEV_PERMIT_TAG_SIZE);
    permit.extend_from_slice(&aad);
    permit.extend_from_slice(canonical);
    permit.extend_from_slice(&tag);
    Ok(permit)
}

/// Verify a dev permit against (network, target, namespace): envelope size,
/// the scope aad, the tag and the embedded command identity. Mirrors
/// `DevConfigAuthorityVerifier::verify_permit`. The device is the permit
/// verifier; the host never re-checks its own freshly-signed permit at
/// runtime (same key, same encoder — a self-check adds no assurance), so this
/// exists for the signer's round-trip tests. Returns the authenticated
/// canonical bytes.
#[cfg(test)]
pub fn dev_permit_verify(
    dev_key: &[u8],
    network: u64,
    target: u64,
    config_namespace: u16,
    authorized_issuer: u64,
    authority_generation: u32,
    permit: &[u8],
) -> Result<Vec<u8>, ConfigError> {
    if permit.len() < CONFIG_DEV_PERMIT_MIN || permit.len() > CONFIG_PERMIT_OBJECT_MAX {
        return Err(ConfigError::Malformed);
    }
    let aad: [u8; CONFIG_PERMIT_AAD_SIZE] =
        permit[..CONFIG_PERMIT_AAD_SIZE].try_into().expect("fixed");
    let canonical = &permit[CONFIG_PERMIT_AAD_SIZE..permit.len() - CONFIG_DEV_PERMIT_TAG_SIZE];
    let tag = &permit[permit.len() - CONFIG_DEV_PERMIT_TAG_SIZE..];
    // Scope binding first (fast reject); the tag authenticates the aad too.
    let expected_aad = config_permit_aad(network, target, config_namespace)?;
    if !constant_time_equal(&aad, &expected_aad) {
        return Err(ConfigError::Stale); // foreign network/target/namespace: denied
    }
    let expected_tag = config_dev_permit_tag(dev_key, &aad, canonical)?;
    if !constant_time_equal(tag, &expected_tag) {
        return Err(ConfigError::Stale); // bad MAC: denied
    }
    let command = routeloom_wire::endpoint::config_command_decode(canonical)
        .map_err(|_| ConfigError::Malformed)?;
    if command.network != network
        || command.target != target
        || command.config_namespace != config_namespace
        || command.authority != authorized_issuer
        || command.authority_generation != authority_generation
    {
        return Err(ConfigError::Stale); // not the configured authority: denied
    }
    Ok(canonical.to_vec())
}

/// recovery_aad = recovery_domain || network u64 || target u64 || ns u16
/// (46 B). Mirror of `config_recovery_aad`.
pub fn config_recovery_aad(
    network: u64,
    target: u64,
    config_namespace: u16,
) -> Result<[u8; CONFIG_RECOVERY_AAD_SIZE], ConfigError> {
    if !config_namespace_valid(config_namespace) {
        return Err(ConfigError::InvalidArgument);
    }
    let mut out = [0_u8; CONFIG_RECOVERY_AAD_SIZE];
    out[..CONFIG_RECOVERY_DOMAIN.len()].copy_from_slice(CONFIG_RECOVERY_DOMAIN);
    let mut cursor = CONFIG_RECOVERY_DOMAIN.len();
    out[cursor..cursor + 8].copy_from_slice(&network.to_be_bytes());
    cursor += 8;
    out[cursor..cursor + 8].copy_from_slice(&target.to_be_bytes());
    cursor += 8;
    out[cursor..cursor + 2].copy_from_slice(&config_namespace.to_be_bytes());
    Ok(out)
}

/// tag = HMAC-SHA256(dev_key, dev_recovery_domain || aad || canonical)[..16].
/// Mirror of `config_dev_recovery_tag` — the canonical must be one RCR2 body.
pub fn config_dev_recovery_tag(
    dev_key: &[u8],
    aad: &[u8; CONFIG_RECOVERY_AAD_SIZE],
    canonical: &[u8],
) -> Result<[u8; CONFIG_DEV_PERMIT_TAG_SIZE], ConfigError> {
    if dev_key.is_empty() || canonical.is_empty() {
        return Err(ConfigError::InvalidArgument);
    }
    let mut input =
        Vec::with_capacity(CONFIG_DEV_RECOVERY_DOMAIN.len() + aad.len() + canonical.len());
    input.extend_from_slice(CONFIG_DEV_RECOVERY_DOMAIN);
    input.extend_from_slice(aad);
    input.extend_from_slice(canonical);
    let mac = hmac_sha256(dev_key, &input);
    let mut tag = [0_u8; CONFIG_DEV_PERMIT_TAG_SIZE];
    tag.copy_from_slice(&mac[..CONFIG_DEV_PERMIT_TAG_SIZE]);
    Ok(tag)
}

/// Sign a canonical RCR2 intent into the dev recovery envelope:
/// object = recovery_aad || rcr2 || tag16. Verified on the device by
/// the dev verifier's recovery leg.
pub fn dev_sign_recovery(
    dev_key: &[u8],
    intent: &ConfigRecoveryIntent,
    canonical: &[u8],
) -> Result<Vec<u8>, ConfigError> {
    if canonical.is_empty()
        || canonical.len() + CONFIG_RECOVERY_AAD_SIZE + CONFIG_DEV_PERMIT_TAG_SIZE
            > CONFIG_DEV_RECOVERY_OBJECT_MAX
    {
        return Err(ConfigError::TooLarge);
    }
    let aad = config_recovery_aad(intent.network, intent.target, intent.config_namespace)?;
    let tag = config_dev_recovery_tag(dev_key, &aad, canonical)?;
    let mut object =
        Vec::with_capacity(CONFIG_RECOVERY_AAD_SIZE + canonical.len() + CONFIG_DEV_PERMIT_TAG_SIZE);
    object.extend_from_slice(&aad);
    object.extend_from_slice(canonical);
    object.extend_from_slice(&tag);
    Ok(object)
}

/// Verify a dev recovery object (round-trip tests only — same argument as
/// `dev_permit_verify`). Returns the authenticated RCR2 canonical.
#[cfg(test)]
pub fn dev_recovery_verify(
    dev_key: &[u8],
    network: u64,
    target: u64,
    config_namespace: u16,
    authorized_issuer: u64,
    authority_generation: u32,
    object: &[u8],
) -> Result<Vec<u8>, ConfigError> {
    use routeloom_wire::endpoint::RCR2_HEADER_SIZE;
    let min = CONFIG_RECOVERY_AAD_SIZE + RCR2_HEADER_SIZE + CONFIG_DEV_PERMIT_TAG_SIZE;
    if object.len() < min || object.len() > CONFIG_PERMIT_OBJECT_MAX {
        return Err(ConfigError::Malformed);
    }
    let aad: [u8; CONFIG_RECOVERY_AAD_SIZE] = object[..CONFIG_RECOVERY_AAD_SIZE]
        .try_into()
        .expect("fixed");
    let canonical = &object[CONFIG_RECOVERY_AAD_SIZE..object.len() - CONFIG_DEV_PERMIT_TAG_SIZE];
    let tag = &object[object.len() - CONFIG_DEV_PERMIT_TAG_SIZE..];
    let expected_aad = config_recovery_aad(network, target, config_namespace)?;
    if !constant_time_equal(&aad, &expected_aad) {
        return Err(ConfigError::Stale);
    }
    let expected_tag = config_dev_recovery_tag(dev_key, &aad, canonical)?;
    if !constant_time_equal(tag, &expected_tag) {
        return Err(ConfigError::Stale);
    }
    let intent = routeloom_wire::endpoint::config_recovery_decode(canonical)
        .map_err(|_| ConfigError::Malformed)?;
    if intent.network != network
        || intent.target != target
        || intent.config_namespace != config_namespace
        || intent.authority != authorized_issuer
        || intent.authority_generation != authority_generation
    {
        return Err(ConfigError::Stale);
    }
    Ok(canonical.to_vec())
}

/// Sign a canonical RCC1/RCR2 command into the restricted COSE_Sign1
/// envelope (config_cose.hpp): protected {1:-9, 4:authority-kid} via the
/// shared protected builder, the profile's own external AAD, attached
/// canonical payload, raw low-S R || S. The envelope assembly is the same
/// construction the trust manifest uses — only the kid namespace (config
/// authority, never a root id) and the AAD differ.
pub fn cose_sign_object(
    signer: &FileAuthoritySigner,
    external_aad: &[u8],
    canonical: &[u8],
) -> Result<Vec<u8>, ConfigError> {
    if canonical.is_empty() || canonical.len() > CONFIG_COSE_OBJECT_MAX {
        return Err(ConfigError::TooLarge);
    }
    let protected = manifest_protected(signer.authority_id());
    let to_sign = cose_sig_structure(&protected, external_aad, canonical)
        .map_err(|_| ConfigError::InvalidArgument)?;
    let signature = signer.sign(&to_sign);
    // Self-check before the envelope may leave the host: the signature
    // must verify under our own public half over the digest both sides
    // compute, with the device's range + low-S rule applied.
    let digest = sha256(&to_sign);
    let signature_bytes: [u8; COSE_SIGNATURE_SIZE] = signature;
    if signature_range_check(&signature_bytes).is_err()
        || !ecdsa_p256_verify(&signer.pubkey(), &digest, &signature_bytes)
    {
        return Err(ConfigError::Malformed);
    }
    let object = manifest_assemble(canonical, signer.authority_id(), &signature)
        .map_err(|_| ConfigError::InvalidArgument)?;
    if object.len() > CONFIG_PERMIT_OBJECT_MAX {
        return Err(ConfigError::TooLarge);
    }
    Ok(object)
}

/// Domain-separated development permit key derivation, mirroring the
/// firmware's `SHA256("RouteLoom/config-dev/v1" || master_key)` (the 25-byte
/// domain has no trailing NUL — distinct from the permit-HMAC domain, which
/// keeps one). `master` is the link development secret, never stored as the
/// permit key itself: the issuer signs under this derived value so config
/// auth is a separate secret from the link PSK. EXPERIMENTAL — not a
/// production identity.
pub fn config_dev_key(master: &[u8]) -> [u8; 32] {
    const KEY_DOMAIN: &[u8] = b"RouteLoom/config-dev/v1";
    let mut material = Vec::with_capacity(KEY_DOMAIN.len() + master.len());
    material.extend_from_slice(KEY_DOMAIN);
    material.extend_from_slice(master);
    sha256(&material)
}

// --- Issuer -----------------------------------------------------------------

/// A recorded ControlChallenge for one (target, namespace): the freshness +
/// CAS inputs `propose` consumes. The remaining apply budget is measured from
/// receipt on the issuer's own clock — never the target's or a wall clock.
#[derive(Clone, Copy, Debug)]
struct ChallengeRecord {
    nonce: [u8; 16],
    target_boot: u64,
    revision: u64,
    active_hash: [u8; 32],
    valid_for_ms: u32,
    received_ms: u64,
    schema: u16,
}

/// What `prepare_propose` produces. `NoChange` consumes neither a
/// sequence, a revision, nor a flash write — it is reported, never
/// silently turned into a permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposeOutcome {
    Draft(Box<ProposeDraft>),
    NoChange,
}

/// A finalized but UNSIGNED proposal: the canonical RCC1 plus the decoded
/// command it was encoded from (the signing step re-derives the AAD and
/// identity from it). Signing happens after the outbox commit, never before.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeDraft {
    pub canonical: Vec<u8>,
    pub command: ConfigCommand,
}

/// The issuer's output for one accepted issuance — shared by the RCC1
/// permit and RCR2 recovery paths (§7.2): the canonical command
/// (committed to the outbox BEFORE signing), the signed object to
/// retransmit verbatim, and the bound operation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedObject {
    /// `ISSUE_KIND_PERMIT` (3) or `ISSUE_KIND_RECOVERY` (4).
    pub kind: u8,
    /// `ISSUE_PROFILE_DEV` (0) or `ISSUE_PROFILE_COSE` (1).
    pub profile: u8,
    pub canonical: Vec<u8>,
    pub object: Vec<u8>,
    pub operation_id: [u8; 16],
    pub authority_sequence: u64,
}

/// The Authority-side issuer (04 §4.3): the single issuance path (no
/// device-side issuer exists). Tracks challenge freshness per (target,
/// namespace); `prepare_*` performs the CAS/revision binding into a
/// finalized canonical, and the profile signer turns a committed
/// canonical into an `IssuedObject`. The SingleAuthority sequence and the
/// outbox commit between them are supplied by the caller per issuance so
/// this core stays pure and testable — the durable commit order lives in
/// the store/dispatch layer. Profile selection is explicit (`profile` +
/// the matching key); an unoffered profile refuses, never falls back.
pub struct ConfigIssuer {
    dev_key: Vec<u8>,
    network: u64,
    authority: u64,
    safety_margin_ms: u32,
    profile: u8,
    cose: Option<FileAuthoritySigner>,
    challenges: HashMap<(u64, u16), ChallengeRecord>,
}

impl ConfigIssuer {
    /// `dev_key` is the domain-separated development permit key (never the
    /// raw link master key). The issuer starts on the dev profile; the
    /// dispatch layer selects COSE and installs the authority key when the
    /// daemon is configured for it.
    pub fn new(dev_key: Vec<u8>, network: u64, authority: u64, safety_margin_ms: u32) -> Self {
        Self {
            dev_key,
            network,
            authority,
            safety_margin_ms,
            profile: ISSUE_PROFILE_DEV,
            cose: None,
            challenges: HashMap::new(),
        }
    }

    /// Select the issuance profile (`ISSUE_PROFILE_DEV`/`ISSUE_PROFILE_COSE`).
    /// An unknown value refuses every later sign — it is never coerced.
    pub fn set_profile(&mut self, profile: u8) {
        self.profile = profile;
    }

    /// Install the COSE authority signer (daemon `--config-authority-key`).
    /// The signer's authority id must equal the configured authority or
    /// every COSE sign refuses — a key for another authority never signs.
    pub fn set_cose_signer(&mut self, signer: FileAuthoritySigner) {
        self.cose = Some(signer);
    }

    pub fn profile(&self) -> u8 {
        self.profile
    }

    /// The (network, authority) this issuer binds into every command —
    /// the lane commits exactly this identity with each reservation.
    pub fn identity(&self) -> (u64, u64) {
        (self.network, self.authority)
    }

    /// Whether the SELECTED profile holds its signing key — a Propose or
    /// Recover against a keyless profile is refused, never signed with an
    /// empty key and never retried under the other profile.
    pub fn ready(&self) -> bool {
        match self.profile {
            ISSUE_PROFILE_DEV => !self.dev_key.is_empty(),
            ISSUE_PROFILE_COSE => self
                .cose
                .as_ref()
                .is_some_and(|signer| signer.authority_id() == self.authority),
            _ => false,
        }
    }

    /// Rebind the issuer identity inputs that are runtime-fed rather than
    /// fixed at construction: `network` comes from the authenticated USB
    /// session (it can change across links), `authority` is the configured
    /// issuer node id. The dispatch layer sets these before each propose so
    /// the signed command names the live network and the daemon's own
    /// authority — never a stale or client-supplied value.
    pub fn set_identity(&mut self, network: u64, authority: u64) {
        self.network = network;
        self.authority = authority;
    }

    /// Record a received Challenge2 for (target, namespace). The remaining
    /// apply budget is measured from THIS receipt on the issuer's clock.
    /// A challenge this ledger refuses REPLACES nothing and evicts any
    /// previously cached record for the same key — a stale nonce/revision
    /// must never be signable by a later propose.
    pub fn note_challenge(
        &mut self,
        challenge: &ControlChallenge,
        target: u64,
        received_ms: u64,
    ) -> Result<(), ConfigError> {
        if !config_namespace_valid(challenge.config_namespace)
            || all_zero(&challenge.challenge_nonce)
            || challenge.target_boot == 0
        {
            self.challenges
                .remove(&(target, challenge.config_namespace));
            return Err(ConfigError::InvalidArgument);
        }
        self.challenges.insert(
            (target, challenge.config_namespace),
            ChallengeRecord {
                nonce: challenge.challenge_nonce,
                target_boot: challenge.target_boot,
                revision: challenge.revision,
                active_hash: challenge.active_hash,
                valid_for_ms: challenge.valid_for_ms,
                received_ms,
                schema: challenge.schema,
            },
        );
        Ok(())
    }

    /// Issue a signed permit for `patch` against the recorded challenge.
    /// `base_snapshot` must be the complete active snapshot bytes the issuer
    /// holds for the target; it is verified against the challenge's
    /// active_hash before signing (the CAS chain). `apply_budget_ms == 0`
    /// requests the whole remaining challenge budget.
    ///
    /// `authority_generation`, `authority_sequence` and `operation_id` are the
    /// ledger/entropy inputs the caller supplies — the issuer binds them
    /// into the command but never invents them. The output is UNSIGNED:
    /// the lane commits it to the outbox, then signs.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_propose(
        &self,
        target: u64,
        config_namespace: u16,
        schema: u16,
        base_snapshot: &[u8],
        patch: &[ConfigField],
        apply_budget_ms: u32,
        now_ms: u64,
        authority_generation: u32,
        authority_sequence: u64,
        operation_id: [u8; 16],
    ) -> Result<ProposeOutcome, ConfigError> {
        if !config_namespace_valid(config_namespace) || all_zero(&operation_id) {
            return Err(ConfigError::InvalidArgument);
        }
        let challenge = self
            .challenges
            .get(&(target, config_namespace))
            .ok_or(ConfigError::ChallengeMissing)?;
        if challenge.schema != schema {
            return Err(ConfigError::InvalidArgument);
        }
        if now_ms < challenge.received_ms {
            return Err(ConfigError::ClockUncertain);
        }
        let elapsed = now_ms - challenge.received_ms;
        if elapsed + u64::from(self.safety_margin_ms) >= u64::from(challenge.valid_for_ms) {
            return Err(ConfigError::Expired);
        }
        let remaining = u64::from(challenge.valid_for_ms)
            .saturating_sub(elapsed)
            .saturating_sub(u64::from(self.safety_margin_ms));
        let apply_within = if apply_budget_ms == 0 {
            remaining
        } else {
            u64::from(apply_budget_ms)
        };
        if apply_within == 0 || apply_within > remaining {
            return Err(ConfigError::Expired);
        }
        let apply_within_ms = apply_within as u32;

        // The base snapshot bytes must be the ones the challenge's active
        // hash commits to — otherwise the CAS chain is broken before signing.
        let base_hash = snapshot_hash(config_namespace, schema, base_snapshot)?;
        if base_hash != challenge.active_hash {
            return Err(ConfigError::Stale);
        }
        let (next, changed) =
            config_patch_apply(base_snapshot, patch).map_err(|_| ConfigError::InvalidArgument)?;
        if !changed {
            return Ok(ProposeOutcome::NoChange);
        }
        let next_hash = snapshot_hash(config_namespace, schema, &next)?;
        if challenge.revision == u64::MAX {
            return Err(ConfigError::InvalidArgument);
        }

        let command = ConfigCommand {
            config_namespace,
            schema,
            network: self.network,
            target,
            authority: self.authority,
            authority_generation,
            authority_sequence,
            operation_id,
            expected_revision: challenge.revision,
            next_revision: challenge.revision + 1,
            base_snapshot_hash: base_hash,
            next_snapshot_hash: next_hash,
            target_boot: challenge.target_boot,
            challenge_nonce: challenge.nonce,
            apply_within_ms,
            fields: patch.to_vec(),
        };
        let mut canonical = Vec::new();
        config_command_encode(&command, &mut canonical)
            .map_err(|_| ConfigError::InvalidArgument)?;
        Ok(ProposeOutcome::Draft(Box::new(ProposeDraft {
            canonical,
            command,
        })))
    }

    /// Finalize an RCR2 recovery intent into its canonical bytes (§5.2):
    /// the operator-chosen mode plus the exact-next (J, R) the target's
    /// RecoveryInfo advertised and the adopted baseline. AdoptKnown binds
    /// the proven survivor by hash alone and carries no snapshot;
    /// Reprovision carries the complete baseline to re-apply, and its
    /// `snapshot_hash` must equal the baseline's domain hash — the
    /// device enforces the same equality before restoring. The output
    /// is UNSIGNED: the lane commits it, then signs.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_recovery(
        &self,
        target: u64,
        config_namespace: u16,
        schema: u16,
        mode: u8,
        new_store_generation: u32,
        new_revision: u64,
        adopted_snapshot_hash: [u8; 32],
        baseline: &[u8],
        authority_generation: u32,
        authority_sequence: u64,
        operation_id: [u8; 16],
    ) -> Result<(ConfigRecoveryIntent, Vec<u8>), ConfigError> {
        if mode == RCR2_MODE_REPROVISION {
            // The carried baseline IS the adopted snapshot: the signed
            // hash must be its domain hash, or the device must refuse
            // the object after a wasted reservation, signature and
            // transfer. Refusing here keeps the mismatch pre-reserve.
            let actual = snapshot_hash(config_namespace, schema, baseline)
                .map_err(|_| ConfigError::InvalidArgument)?;
            if actual != adopted_snapshot_hash {
                return Err(ConfigError::InvalidArgument);
            }
        }
        let intent = ConfigRecoveryIntent {
            mode,
            config_namespace,
            schema,
            network: self.network,
            target,
            authority: self.authority,
            authority_generation,
            authority_sequence,
            operation_id,
            new_store_generation,
            new_revision,
            snapshot_hash: adopted_snapshot_hash,
            baseline: baseline.to_vec(),
        };
        let mut canonical = Vec::new();
        config_recovery_encode(&intent, &mut canonical)
            .map_err(|_| ConfigError::InvalidArgument)?;
        Ok((intent, canonical))
    }

    /// Sign a committed permit canonical under the SELECTED profile into
    /// the shared `IssuedObject`. The AAD is re-derived from this
    /// issuer's own identity — a caller-supplied AAD is never accepted.
    /// Refuses (never falls back) when the profile is unknown or its key
    /// is absent or bound to another authority.
    pub fn sign_permit(
        &self,
        draft: &ProposeDraft,
        authority_sequence: u64,
    ) -> Result<IssuedObject, ConfigError> {
        // The envelope identity must be this issuer's own — a draft bound
        // to another network/authority never signs, even well-formed.
        if draft.command.network != self.network || draft.command.authority != self.authority {
            return Err(ConfigError::InvalidArgument);
        }
        let aad = config_permit_aad(
            draft.command.network,
            draft.command.target,
            draft.command.config_namespace,
        )?;
        let object = match self.profile {
            ISSUE_PROFILE_DEV => dev_sign_permit(&self.dev_key, &draft.command, &draft.canonical)?,
            ISSUE_PROFILE_COSE => self.cose_sign(&aad, &draft.canonical)?,
            _ => return Err(ConfigError::Unsupported),
        };
        Ok(IssuedObject {
            kind: ISSUE_KIND_PERMIT,
            profile: self.profile,
            canonical: draft.canonical.clone(),
            object,
            operation_id: draft.command.operation_id,
            authority_sequence,
        })
    }

    /// Sign a committed recovery canonical under the SELECTED profile.
    /// Same key/profile refusal contract as `sign_permit`.
    pub fn sign_recovery(
        &self,
        intent: &ConfigRecoveryIntent,
        canonical: &[u8],
        authority_sequence: u64,
    ) -> Result<IssuedObject, ConfigError> {
        if intent.network != self.network || intent.authority != self.authority {
            return Err(ConfigError::InvalidArgument);
        }
        let aad = config_recovery_aad(intent.network, intent.target, intent.config_namespace)?;
        let object = match self.profile {
            ISSUE_PROFILE_DEV => dev_sign_recovery(&self.dev_key, intent, canonical)?,
            ISSUE_PROFILE_COSE => self.cose_sign(&aad, canonical)?,
            _ => return Err(ConfigError::Unsupported),
        };
        Ok(IssuedObject {
            kind: ISSUE_KIND_RECOVERY,
            profile: self.profile,
            canonical: canonical.to_vec(),
            object,
            operation_id: intent.operation_id,
            authority_sequence,
        })
    }

    /// The COSE leg both issuance paths share: the installed authority
    /// signer over the profile's own AAD. A missing signer — or one
    /// bound to another authority — refuses; the dev key is never
    /// consulted as a fallback.
    fn cose_sign(&self, aad: &[u8], canonical: &[u8]) -> Result<Vec<u8>, ConfigError> {
        let signer = self.cose.as_ref().ok_or(ConfigError::Unsupported)?;
        if signer.authority_id() != self.authority {
            return Err(ConfigError::Unsupported);
        }
        cose_sign_object(signer, aad, canonical)
    }
}

// --- Config lane (USB host_ops request lifecycle) -----------------------------
//
// The lane drives one high-level client operation to completion across the
// USB round trips it needs. The device enforces a single-transaction bound
// (one outstanding query AND one outstanding transfer); the lane keeps the
// tighter host-side bound of ONE outstanding request at a time so the step
// sequence is unambiguous. Each step emits an encoded host_ops body tagged
// with a fresh request id; the matching async reply lands on `on_reply`.
//
// Honesty rules (05 §5.6): an ObjectAck/Ok means the device proved the mesh
// step — never a config verdict. A query deadline produces Timeout; a permit
// transfer deadline produces Indeterminate; a malformed or unmatched reply is
// a protocol error, never a silent retry.

/// Round-trip budgets mirroring config_wire_const.
pub const CONFIG_QUERY_TIMEOUT_MS: u64 = 3_000;
pub const CONFIG_PERMIT_TIMEOUT_MS: u64 = 15_000;

/// A client request the lane drives. `Propose` reads target capability,
/// then challenge -> commit -> sign -> permit -> status. `Recover` reads
/// target capability and floors, then commit -> sign -> recovery transfer
/// -> status; the others are single queries.
#[derive(Clone, Debug)]
pub enum ConfigRequest {
    /// Issue a ChallengeQuery and report the ControlChallenge body.
    Challenge {
        target: u64,
        config_namespace: u16,
        schema: u16,
    },
    /// Issue a StatusQuery for `operation_id` and report the ControlStatus
    /// body — the real verdict of the config operation that id names.
    Status {
        target: u64,
        config_namespace: u16,
        operation_id: [u8; 16],
    },
    /// Challenge then commit then sign `patch` against `base_snapshot`
    /// then transfer the permit then read the operation's terminal status.
    /// `apply_budget_ms==0` requests the whole remaining challenge budget.
    Propose {
        target: u64,
        config_namespace: u16,
        schema: u16,
        base_snapshot: Vec<u8>,
        patch: Vec<ConfigField>,
        apply_budget_ms: u32,
    },
    /// Commit then sign an RCR2 recovery intent against the operator-read
    /// RecoveryInfo baseline, transfer it on the kind-4 lane (0x24), then
    /// read the operation's terminal status. `mode` is AdoptKnown (0, binds
    /// the proven survivor by `snapshot_hash`, empty `baseline`) or
    /// Reprovision (1, carries the complete `baseline` to re-apply);
    /// (`new_store_generation`, `new_revision`) must name the floor's
    /// exact next — the target refuses anything else honestly.
    Recover {
        target: u64,
        config_namespace: u16,
        schema: u16,
        mode: u8,
        new_store_generation: u32,
        new_revision: u64,
        snapshot_hash: [u8; 32],
        baseline: Vec<u8>,
    },
    /// Transfer a signed trust manifest (RTM1, 0x25) then read back the
    /// target's TrustStatus (0x26) as the receipt. Deliberately ledger-
    /// free: trust install is independent of the config authority (§6.3).
    /// `network` binds the status read to this mesh.
    TrustInstall {
        target: u64,
        network: u64,
        manifest: Vec<u8>,
    },
    /// Query one target's TrustStatus (0x26) — the receipt for an install
    /// and the generation/image evidence for a rotation.
    TrustStatus { target: u64, network: u64 },
    /// Query one target's RecoveryInfo (0x27) — the floor readings and
    /// the survivor/testimony hashes the RCR2 issuance binds.
    RecoveryInfo {
        target: u64,
        network: u64,
        config_namespace: u16,
    },
}

/// The terminal outcome the lane reports for one request — never a bare
/// transport success. `PermitAssembled` is the honest mid-state: the object
/// landed at the target, but the config verdict is the Status body's
/// phase/reason, which a follow-up Status step reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigOutcome {
    /// A ControlChallenge body arrived (propose step or challenge query).
    Challenged(ControlChallenge),
    /// A ControlStatus body arrived — the operation's real verdict.
    Statused(ControlStatus),
    /// The permit object assembled at the target (0x21 Ok) — NOT active.
    /// Carries the issued device operation_id when the lane minted one, so
    /// `config.get` can still name the operation a follow-up StatusQuery
    /// would read.
    PermitAssembled(Option<[u8; 16]>),
    /// The patch was a no-op (NO_CHANGE): nothing was signed or sent.
    NoChange,
    /// Device-side refusal (Busy/Denied/Unsupported/Invalid/NoRoute).
    Refused(ConfigOpsResult),
    /// Issuer-side refusal: the proposal's base snapshot failed the CAS
    /// check against the challenge's active_hash — a client fault naming
    /// a stale base, never a wire fault and never a success.
    RefusedStale,
    /// Issuer-side refusal: the selected issuance profile is unoffered —
    /// unknown profile, missing key, or a key bound to another authority.
    /// Refused BEFORE any sequence reservation, signature, or mesh send;
    /// the other profile is never attempted as a fallback.
    RefusedProfile,
    /// A TrustStatus body (0x26) — the install receipt or a standalone
    /// status read. The body echoed the query nonce and names the
    /// queried network; anything else is a ProtocolError.
    TrustStatus(TrustStatus),
    /// A RecoveryInfo body (0x27) — the floor/readiness evidence the
    /// operator's RCR2 baseline binds.
    RecoveryInfo(RecoveryInfo),
    /// The target did not answer a query inside the window.
    Timeout,
    /// A permit transfer could not be proven (deadline / torn exchange).
    /// Carries the issued device operation_id when the propose had already
    /// minted one — the device may hold that operation, so the caller can
    /// keep querying it — and None when failure preceded issuance.
    Indeterminate(Option<[u8; 16]>),
    /// A malformed, mismatched or out-of-turn reply.
    ProtocolError,
}

/// What the lane wants the host to do next for the current request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigStep {
    /// Emit this host_ops body under `request` on the wire.
    Emit { request: u64, body: Vec<u8> },
    /// The request resolved; report `outcome` to the caller.
    Done(ConfigOutcome),
}

enum Phase {
    /// Waiting on a 0x23 reply carrying the ControlChallenge body. The
    /// reply must echo the (schema, client_nonce) the query emitted — a
    /// body answering a different query is a protocol fault, not input.
    Challenge { schema: u16, client_nonce: [u8; 16] },
    /// Waiting on a transfer ack (0x21 permit / 0x24 recovery / 0x25
    /// trust, result-only) before the follow-up read. `sub` names the
    /// expected reply subcommand.
    Transfer { sub: u8 },
    /// Waiting on a trust/root query reply (0x26 TrustStatus / 0x27
    /// RecoveryInfo). The body must echo the emitted nonce and name the
    /// queried network — a body bound to another query or mesh is a
    /// protocol fault, never evidence.
    TrustQuery {
        sub: u8,
        network: u64,
        nonce: [u8; 16],
    },
    /// Waiting on a 0x22 reply carrying the ControlStatus body. The body
    /// must echo the queried operation_id.
    Status { operation_id: [u8; 16] },
}

struct InFlight {
    request: u64,
    phase: Phase,
    deadline_ms: u64,
    /// The request's target — every ConfigReply echoes it back.
    target: u64,
    /// The request's namespace — a challenge/status body must echo it.
    config_namespace: u16,
}

/// Per-request state for a Propose in progress: the inputs the challenge
/// reply signs against. The authority sequence is NOT here — it is
/// reserved from the ledger after the challenge lands, just before the
/// outbox commit. Cleared at sign time; the follow-up status read rides
/// `PendingStatus` instead.
/// Entropy draw for operation_id / client_nonce, injected so tests are
/// deterministic — a `&mut [u8]` fill, same contract as `EntropySource`.
type EntropyFn = Box<dyn FnMut(&mut [u8])>;

#[derive(Clone)]
struct ProposeState {
    target: u64,
    config_namespace: u16,
    schema: u16,
    base_snapshot: Vec<u8>,
    patch: Vec<ConfigField>,
    apply_budget_ms: u32,
    operation_id: [u8; 16],
    authority_generation: u32,
}

struct RecoverState {
    target: u64,
    config_namespace: u16,
    schema: u16,
    mode: u8,
    new_store_generation: u32,
    new_revision: u64,
    snapshot_hash: [u8; 32],
    baseline: Vec<u8>,
}

/// An issued object in flight toward its status read — shared by the
/// propose and recover paths. Set when the signed transfer emits,
/// consumed by the follow-up StatusQuery; also names the operation a
/// transfer deadline leaves indeterminate.
struct PendingStatus {
    target: u64,
    config_namespace: u16,
    operation_id: [u8; 16],
}

/// The lane state machine. `next_request` mirrors the dispatcher's request-id
/// allocation; entropy for operation_id / client_nonce is injected so tests
/// are deterministic.
pub struct ConfigLane {
    issuer: ConfigIssuer,
    next_request: u64,
    in_flight: Option<InFlight>,
    propose: Option<ProposeState>,
    recover: Option<RecoverState>,
    pending: Option<PendingStatus>,
    /// A trust install awaiting its receipt read: the (target, network)
    /// the 0x26 follow-up queries. Set when the 0x25 transfer emits.
    trust_followup: Option<(u64, u64)>,
    /// Authority generation the dispatch layer supplies per issuance —
    /// bound into every signed command. The sequence is reserved from the
    /// ledger per issuance instead, just before the outbox commit.
    authority_generation: u32,
    /// Entropy draws (operation_id, client_nonce); injected for tests.
    entropy: EntropyFn,
    nonce_counter: u64,
}

impl ConfigLane {
    pub fn new(issuer: ConfigIssuer, authority_generation: u32, entropy: EntropyFn) -> Self {
        Self {
            issuer,
            next_request: 0,
            in_flight: None,
            propose: None,
            recover: None,
            pending: None,
            trust_followup: None,
            authority_generation,
            entropy,
            nonce_counter: 0,
        }
    }

    pub fn set_authority(&mut self, generation: u32) {
        self.authority_generation = generation;
    }

    /// Rebind the issuer's (network, authority) before a propose — the
    /// network is the live session's mesh id and the authority is the
    /// daemon's configured issuer node id, both supplied by the dispatch
    /// layer. Challenge/Status requests do not sign, so this is only
    /// consulted on the Propose path.
    pub fn set_issuer_identity(&mut self, network: u64, authority: u64) {
        self.issuer.set_identity(network, authority);
    }

    fn alloc_request(&mut self) -> u64 {
        self.next_request = self.next_request.wrapping_add(1).max(1);
        self.next_request
    }

    fn draw_nonce(&mut self) -> [u8; 16] {
        let mut nonce = [0_u8; 16];
        (self.entropy)(&mut nonce);
        if all_zero(&nonce) {
            self.nonce_counter = self.nonce_counter.wrapping_add(1);
            nonce[0] = 0x52;
            nonce[8..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        }
        nonce
    }

    pub fn busy(&self) -> bool {
        self.in_flight.is_some()
    }

    /// Whether the issuer carries a signing key — a Propose against a lane
    /// with no key must be refused, never signed with an empty key.
    pub fn issuer_ready(&self) -> bool {
        self.issuer.ready()
    }

    /// Begin a client request. Returns the first step (an Emit) or a Done
    /// when the request is trivially refusable. Busy while a request is in
    /// flight — the caller must not submit a second. `commit` is the
    /// issuance ledger: Propose and Recover read the target's capability
    /// first. Propose then challenges, while Recover checks the live floor.
    /// Both commit and sign only after the corresponding reply lands.
    pub fn submit<C: ConfigAuthorityLedger>(
        &mut self,
        _commit: &mut C,
        request: ConfigRequest,
        now_ms: u64,
    ) -> ConfigStep {
        if self.in_flight.is_some() {
            return ConfigStep::Done(ConfigOutcome::Refused(ConfigOpsResult::Busy));
        }
        match request {
            ConfigRequest::Challenge {
                target,
                config_namespace,
                schema,
            } => self.emit_challenge(target, config_namespace, schema, now_ms),
            ConfigRequest::Status {
                target,
                config_namespace,
                operation_id,
            } => self.emit_status(target, config_namespace, operation_id, now_ms),
            ConfigRequest::Propose {
                target,
                config_namespace,
                schema,
                base_snapshot,
                patch,
                apply_budget_ms,
            } => {
                // Profile/key readiness refuses here, before the challenge
                // even emits — no sequence exists yet to waste.
                if !self.issuer.ready() {
                    return ConfigStep::Done(ConfigOutcome::RefusedProfile);
                }
                let operation_id = self.draw_nonce();
                self.propose = Some(ProposeState {
                    target,
                    config_namespace,
                    schema,
                    base_snapshot,
                    patch,
                    apply_budget_ms,
                    operation_id,
                    authority_generation: self.authority_generation,
                });
                let (network, _) = self.issuer.identity();
                let step = self.emit_trust_query(
                    SUB_CONFIG_RECOVERY_INFO,
                    target,
                    network,
                    config_namespace,
                    now_ms,
                );
                if matches!(step, ConfigStep::Done(_)) {
                    self.clear_issue();
                }
                step
            }
            ConfigRequest::Recover {
                target,
                config_namespace,
                schema,
                mode,
                new_store_generation,
                new_revision,
                snapshot_hash,
                baseline,
            } => self.begin_recover(
                target,
                config_namespace,
                schema,
                mode,
                new_store_generation,
                new_revision,
                snapshot_hash,
                baseline,
                now_ms,
            ),
            ConfigRequest::TrustInstall {
                target,
                network,
                manifest,
            } => self.submit_trust_install(target, network, &manifest, now_ms),
            ConfigRequest::TrustStatus { target, network } => {
                self.emit_trust_query(SUB_CONFIG_TRUST_STATUS, target, network, 0, now_ms)
            }
            ConfigRequest::RecoveryInfo {
                target,
                network,
                config_namespace,
            } => self.emit_trust_query(
                SUB_CONFIG_RECOVERY_INFO,
                target,
                network,
                config_namespace,
                now_ms,
            ),
        }
    }

    /// Read the target's recovery version, selected profile and live floor
    /// before any sequence or signature is spent. The target independently
    /// checks the values again when it receives the signed object.
    #[allow(clippy::too_many_arguments)]
    fn begin_recover(
        &mut self,
        target: u64,
        config_namespace: u16,
        schema: u16,
        mode: u8,
        new_store_generation: u32,
        new_revision: u64,
        snapshot_hash: [u8; 32],
        baseline: Vec<u8>,
        now_ms: u64,
    ) -> ConfigStep {
        if !self.issuer.ready() {
            return ConfigStep::Done(ConfigOutcome::RefusedProfile);
        }
        if let Err(error) = self.issuer.prepare_recovery(
            target,
            config_namespace,
            schema,
            mode,
            new_store_generation,
            new_revision,
            snapshot_hash,
            &baseline,
            self.authority_generation,
            1,
            [1; 16],
        ) {
            return ConfigStep::Done(map_issue_error(error));
        }
        let (network, _) = self.issuer.identity();
        self.recover = Some(RecoverState {
            target,
            config_namespace,
            schema,
            mode,
            new_store_generation,
            new_revision,
            snapshot_hash,
            baseline,
        });
        let step = self.emit_trust_query(
            SUB_CONFIG_RECOVERY_INFO,
            target,
            network,
            config_namespace,
            now_ms,
        );
        if matches!(step, ConfigStep::Done(_)) {
            self.clear_issue();
        }
        step
    }

    /// The Recover submit: pure input/profile checks, then reserve,
    /// then the finalized canonical bind, then the profile sign, then the
    /// signed-original commit — and only then the 0x24 transfer. Every
    /// refusal precedes the next durable side effect: nothing is
    /// reserved for an input the codec rejects, and nothing is signed
    /// for a reservation the store refused.
    #[allow(clippy::too_many_arguments)]
    fn submit_recover<C: ConfigAuthorityLedger>(
        &mut self,
        commit: &mut C,
        target: u64,
        config_namespace: u16,
        schema: u16,
        mode: u8,
        new_store_generation: u32,
        new_revision: u64,
        snapshot_hash: [u8; 32],
        baseline: &[u8],
        now_ms: u64,
    ) -> ConfigStep {
        if !self.issuer.ready() {
            return ConfigStep::Done(ConfigOutcome::RefusedProfile);
        }
        // Shape first, with a throwaway sequence: an input the codec
        // rejects must not consume a reservation.
        let operation_id = self.draw_nonce();
        let generation = self.authority_generation;
        if let Err(error) = self.issuer.prepare_recovery(
            target,
            config_namespace,
            schema,
            mode,
            new_store_generation,
            new_revision,
            snapshot_hash,
            baseline,
            generation,
            /*authority_sequence=*/ 1,
            operation_id,
        ) {
            return ConfigStep::Done(map_issue_error(error));
        }
        let (network, authority) = self.issuer.identity();
        let sequence = match commit.issue_reserve(&IssueIdentity {
            kind: ISSUE_KIND_RECOVERY,
            op_id: operation_id,
            target,
            namespace: config_namespace,
            profile: self.issuer.profile(),
            authority,
            generation,
            network,
        }) {
            Ok(sequence) => sequence,
            Err(refusal) => return ConfigStep::Done(map_issue_refusal(refusal)),
        };
        // The finalized canonical names the reserved sequence; it binds
        // to the outbox before any signature may exist over it.
        let (intent, canonical) = match self.issuer.prepare_recovery(
            target,
            config_namespace,
            schema,
            mode,
            new_store_generation,
            new_revision,
            snapshot_hash,
            baseline,
            generation,
            sequence,
            operation_id,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return ConfigStep::Done(map_issue_error(error)),
        };
        if let Err(refusal) = commit.issue_bind(&operation_id, &canonical) {
            return ConfigStep::Done(map_issue_refusal(refusal));
        }
        let issued = match self.issuer.sign_recovery(&intent, &canonical, sequence) {
            Ok(issued) => issued,
            Err(error) => return ConfigStep::Done(map_issue_error(error)),
        };
        if let Err(refusal) = commit.issue_signed(&operation_id, &issued.object) {
            return ConfigStep::Done(map_issue_refusal(refusal));
        }
        self.pending = Some(PendingStatus {
            target,
            config_namespace,
            operation_id,
        });
        self.emit_transfer(
            SUB_CONFIG_RECOVER,
            target,
            config_namespace,
            issued.object,
            now_ms,
        )
    }

    /// The TrustInstall submit: the manifest is an offline-signed RTM1 —
    /// the lane transfers it verbatim on 0x25 and reads back the
    /// target's TrustStatus as the receipt. No ledger, no authority
    /// gate: trust delivery is independent of config issuance (§6.3).
    fn submit_trust_install(
        &mut self,
        target: u64,
        network: u64,
        manifest: &[u8],
        now_ms: u64,
    ) -> ConfigStep {
        if target == 0 || target == u64::MAX || network == 0 || network == u64::MAX {
            return ConfigStep::Done(ConfigOutcome::Refused(ConfigOpsResult::Invalid));
        }
        // Structural check only — the target's TrustView verifies the
        // signature. A malformed envelope refuses before any mesh send.
        if routeloom_provision::manifest::manifest_parse(manifest).is_err() {
            return ConfigStep::Done(ConfigOutcome::Refused(ConfigOpsResult::Invalid));
        }
        self.trust_followup = Some((target, network));
        self.emit_transfer(
            SUB_CONFIG_TRUST,
            target,
            /*config_namespace=*/ 0,
            manifest.to_vec(),
            now_ms,
        )
    }

    /// Emit a 0x26/0x27 query with a fresh nonce the reply body must
    /// echo. `config_namespace` rides only the 0x27 leg.
    fn emit_trust_query(
        &mut self,
        sub: u8,
        target: u64,
        network: u64,
        config_namespace: u16,
        now_ms: u64,
    ) -> ConfigStep {
        if target == 0 || target == u64::MAX || network == 0 || network == u64::MAX {
            return ConfigStep::Done(ConfigOutcome::Refused(ConfigOpsResult::Invalid));
        }
        let nonce = self.draw_nonce();
        let request = self.alloc_request();
        let body = if sub == SUB_CONFIG_RECOVERY_INFO {
            if !config_namespace_valid(config_namespace) {
                return ConfigStep::Done(ConfigOutcome::Refused(ConfigOpsResult::Invalid));
            }
            host_ops::encode_config_recovery_info(&host_ops::ConfigRecoveryInfoRequest {
                target,
                network,
                config_namespace,
                nonce,
            })
        } else {
            host_ops::encode_config_trust_status(&host_ops::ConfigTrustStatusRequest {
                target,
                network,
                nonce,
            })
        };
        let body = match body {
            Ok(body) => body,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        self.in_flight = Some(InFlight {
            request,
            phase: Phase::TrustQuery {
                sub,
                network,
                nonce,
            },
            deadline_ms: now_ms + CONFIG_QUERY_TIMEOUT_MS,
            target,
            config_namespace,
        });
        ConfigStep::Emit { request, body }
    }

    fn emit_challenge(
        &mut self,
        target: u64,
        config_namespace: u16,
        schema: u16,
        now_ms: u64,
    ) -> ConfigStep {
        let request = self.alloc_request();
        let client_nonce = self.draw_nonce();
        let body = host_ops::encode_config_challenge(&host_ops::ConfigChallengeRequest {
            target,
            config_namespace,
            schema,
            client_nonce,
        });
        self.in_flight = Some(InFlight {
            request,
            phase: Phase::Challenge {
                schema,
                client_nonce,
            },
            deadline_ms: now_ms + CONFIG_QUERY_TIMEOUT_MS,
            target,
            config_namespace,
        });
        ConfigStep::Emit { request, body }
    }

    fn emit_status(
        &mut self,
        target: u64,
        config_namespace: u16,
        operation_id: [u8; 16],
        now_ms: u64,
    ) -> ConfigStep {
        let request = self.alloc_request();
        let body = host_ops::encode_config_query(&host_ops::ConfigQueryRequest {
            target,
            config_namespace,
            operation_id,
        });
        self.in_flight = Some(InFlight {
            request,
            phase: Phase::Status { operation_id },
            deadline_ms: now_ms + CONFIG_QUERY_TIMEOUT_MS,
            target,
            config_namespace,
        });
        ConfigStep::Emit { request, body }
    }

    /// Emit a signed-object transfer: 0x21 for a kind-3 permit, 0x24 for
    /// a kind-4 recovery object, 0x25 for a kind-5 trust manifest. Same
    /// layout (target + opaque object), same result-only ack — only the
    /// subcommand routes the lane.
    fn emit_transfer(
        &mut self,
        sub: u8,
        target: u64,
        config_namespace: u16,
        object: Vec<u8>,
        now_ms: u64,
    ) -> ConfigStep {
        let request = self.alloc_request();
        let body = if sub == SUB_CONFIG_RECOVER {
            host_ops::encode_config_recover(&host_ops::ConfigRecoverRequest { target, object })
        } else if sub == SUB_CONFIG_TRUST {
            host_ops::encode_config_trust(&host_ops::ConfigTrustRequest {
                target,
                manifest: object,
            })
        } else {
            host_ops::encode_config_permit(&host_ops::ConfigPermitRequest {
                target,
                permit: object,
            })
        };
        let body = match body {
            Ok(body) => body,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        self.in_flight = Some(InFlight {
            request,
            phase: Phase::Transfer { sub },
            deadline_ms: now_ms + CONFIG_PERMIT_TIMEOUT_MS,
            target,
            config_namespace,
        });
        ConfigStep::Emit { request, body }
    }

    /// Drop the in-progress issuance/install state (propose inputs, any
    /// pending follow-up) when the exchange tears.
    fn clear_issue(&mut self) {
        self.propose = None;
        self.recover = None;
        self.pending = None;
        self.trust_followup = None;
    }

    /// The device operation id an indeterminate transfer leaves behind —
    /// the follow-up status read (or a later explicit query) names it.
    fn pending_op_id(&mut self) -> Option<[u8; 16]> {
        self.recover = None;
        if let Some(pending) = self.pending.take() {
            return Some(pending.operation_id);
        }
        self.propose.take().map(|p| p.operation_id)
    }

    /// Consume an inbound reply body for `request`. `inner` is the verified
    /// host_ops inner body (schema|sub|len|payload). Returns Done when the
    /// request resolved, or the next Emit step for a multi-step propose.
    /// `commit` is the issuance ledger the challenge reply commits
    /// through (reserve → bind → sign → store) before the transfer emits.
    pub fn on_reply<C: ConfigAuthorityLedger>(
        &mut self,
        commit: &mut C,
        request: u64,
        inner: &[u8],
        now_ms: u64,
    ) -> ConfigStep {
        let Some(in_flight) = self.in_flight.take() else {
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        };
        if in_flight.request != request {
            // A reply naming a different lane id means the exchange is
            // torn upstream: the outstanding request can never resolve
            // cleanly now, so the lane clears rather than staying armed
            // behind an op that is already resolving ProtocolError.
            self.clear_issue();
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        match in_flight.phase {
            Phase::Challenge {
                schema,
                client_nonce,
            } => self.on_challenge_reply(
                commit,
                inner,
                in_flight.target,
                in_flight.config_namespace,
                schema,
                client_nonce,
                now_ms,
            ),
            Phase::Transfer { sub } => self.on_transfer_reply(sub, inner, in_flight.target, now_ms),
            Phase::TrustQuery {
                sub,
                network,
                nonce,
            } => self.on_trust_query_reply(
                commit,
                sub,
                inner,
                in_flight.target,
                in_flight.config_namespace,
                network,
                nonce,
                now_ms,
            ),
            Phase::Status { operation_id } => self.on_status_reply(
                commit,
                inner,
                in_flight.target,
                in_flight.config_namespace,
                operation_id,
                now_ms,
            ),
        }
    }

    /// A frame the outbound queue refused — provably never reached the device.
    /// Resolve the outstanding request honestly rather than leaving it to time
    /// out: a dropped query is Timeout-adjacent, a dropped transfer Indeterminate.
    pub fn on_dropped(&mut self, request: u64) -> ConfigStep {
        let Some(in_flight) = self.in_flight.take() else {
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        };
        if in_flight.request != request {
            // Same torn-exchange rule as on_reply: a mismatched drop
            // notification cannot resolve the outstanding request, and the
            // lane must not stay armed behind an already-resolved op.
            self.clear_issue();
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let operation_id = self.pending_op_id();
        ConfigStep::Done(match in_flight.phase {
            Phase::Transfer { .. } => ConfigOutcome::Indeterminate(operation_id),
            _ => ConfigOutcome::Timeout,
        })
    }

    /// Deadline enforcement. A query deadline -> Timeout; a transfer deadline
    /// -> Indeterminate (the object may have assembled without the ack).
    pub fn poll(&mut self, now_ms: u64) -> Option<ConfigOutcome> {
        let in_flight = self.in_flight.as_ref()?;
        if now_ms < in_flight.deadline_ms {
            return None;
        }
        let phase = self.in_flight.take().map(|i| i.phase)?;
        let operation_id = self.pending_op_id();
        Some(match phase {
            Phase::Transfer { .. } => ConfigOutcome::Indeterminate(operation_id),
            _ => ConfigOutcome::Timeout,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn on_challenge_reply<C: ConfigAuthorityLedger>(
        &mut self,
        commit: &mut C,
        inner: &[u8],
        target: u64,
        config_namespace: u16,
        schema: u16,
        client_nonce: [u8; 16],
        now_ms: u64,
    ) -> ConfigStep {
        let reply = match host_ops::decode_config_reply(inner, SUB_CONFIG_CHALLENGE) {
            Ok(reply) => reply,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        // A reply must echo the query's target: a refusal naming a
        // different target is a mismatched reply, never a claimed outcome.
        if reply.target != target {
            self.clear_issue();
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let result = match ConfigOpsResult::try_from_u16(reply.result) {
            Ok(result) => result,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if result != ConfigOpsResult::Ok {
            let operation_id = self.pending_op_id();
            return ConfigStep::Done(map_refusal(result, operation_id));
        }
        let challenge = match control_challenge_decode(&reply.body) {
            Ok(challenge) => challenge,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        // The body must answer THIS query: namespace, schema and the
        // emitted client_nonce all echo. A body bound to a different
        // query (stale replay, crossed wire) is a protocol fault — it may
        // never seed the challenge ledger the permit is signed against.
        if challenge.config_namespace != config_namespace
            || challenge.schema != schema
            || challenge.client_nonce != client_nonce
        {
            self.clear_issue();
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        if self.propose.is_none() {
            // Standalone challenge query: report the body, done.
            return ConfigStep::Done(ConfigOutcome::Challenged(challenge));
        }
        // Propose path: record the challenge, draft the canonical, then
        // reserve → bind → sign → store through the ledger before the
        // transfer emits. The ProposeState clears at sign time; the
        // follow-up StatusQuery rides the shared PendingStatus.
        let propose = self.propose.as_ref().expect("checked").clone();
        if let Err(error) = self
            .issuer
            .note_challenge(&challenge, propose.target, now_ms)
        {
            // A challenge the ledger refuses leaves NO cached record —
            // signing a later propose against a stale nonce/revision would
            // mint a permit the target must reject.
            self.clear_issue();
            return ConfigStep::Done(map_issue_error(error));
        }
        // Shape first with a throwaway sequence (same rule as recover:
        // nothing is reserved for a base the CAS check rejects), then the
        // real draft over the reserved value.
        let shape = self.issuer.prepare_propose(
            propose.target,
            propose.config_namespace,
            propose.schema,
            &propose.base_snapshot,
            &propose.patch,
            propose.apply_budget_ms,
            now_ms,
            propose.authority_generation,
            /*authority_sequence=*/ 1,
            propose.operation_id,
        );
        match shape {
            Ok(ProposeOutcome::Draft(_)) => {}
            Ok(ProposeOutcome::NoChange) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::NoChange);
            }
            Err(error) => {
                self.clear_issue();
                return ConfigStep::Done(map_issue_error(error));
            }
        }
        let (network, authority) = self.issuer.identity();
        let sequence = match commit.issue_reserve(&IssueIdentity {
            kind: ISSUE_KIND_PERMIT,
            op_id: propose.operation_id,
            target: propose.target,
            namespace: propose.config_namespace,
            profile: self.issuer.profile(),
            authority,
            generation: propose.authority_generation,
            network,
        }) {
            Ok(sequence) => sequence,
            Err(refusal) => {
                self.clear_issue();
                return ConfigStep::Done(map_issue_refusal(refusal));
            }
        };
        let draft = match self.issuer.prepare_propose(
            propose.target,
            propose.config_namespace,
            propose.schema,
            &propose.base_snapshot,
            &propose.patch,
            propose.apply_budget_ms,
            now_ms,
            propose.authority_generation,
            sequence,
            propose.operation_id,
        ) {
            Ok(ProposeOutcome::Draft(draft)) => draft,
            Ok(ProposeOutcome::NoChange) => {
                // Impossible: the same inputs drafted above. A NoChange
                // here would mean the inputs mutated mid-issuance.
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
            Err(error) => {
                self.clear_issue();
                return ConfigStep::Done(map_issue_error(error));
            }
        };
        if let Err(refusal) = commit.issue_bind(&propose.operation_id, &draft.canonical) {
            self.clear_issue();
            return ConfigStep::Done(map_issue_refusal(refusal));
        }
        let issued = match self.issuer.sign_permit(&draft, sequence) {
            Ok(issued) => issued,
            Err(error) => {
                self.clear_issue();
                return ConfigStep::Done(map_issue_error(error));
            }
        };
        if let Err(refusal) = commit.issue_signed(&propose.operation_id, &issued.object) {
            self.clear_issue();
            return ConfigStep::Done(map_issue_refusal(refusal));
        }
        self.propose = None;
        self.pending = Some(PendingStatus {
            target: propose.target,
            config_namespace: propose.config_namespace,
            operation_id: propose.operation_id,
        });
        self.emit_transfer(
            SUB_CONFIG_PERMIT,
            propose.target,
            propose.config_namespace,
            issued.object,
            now_ms,
        )
    }

    fn on_transfer_reply(&mut self, sub: u8, inner: &[u8], target: u64, now_ms: u64) -> ConfigStep {
        let reply = match host_ops::decode_config_reply(inner, sub) {
            Ok(reply) => reply,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if reply.target != target {
            self.clear_issue();
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let result = match ConfigOpsResult::try_from_u16(reply.result) {
            Ok(result) => result,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if result != ConfigOpsResult::Ok {
            let operation_id = if sub == SUB_CONFIG_TRUST {
                self.trust_followup = None;
                None
            } else {
                self.pending_op_id()
            };
            return ConfigStep::Done(map_refusal(result, operation_id));
        }
        if sub == SUB_CONFIG_TRUST {
            // The manifest landed — NOT a trust verdict. Read the
            // target's TrustStatus back as the install receipt.
            let Some((target, network)) = self.trust_followup.take() else {
                return ConfigStep::Done(ConfigOutcome::PermitAssembled(None));
            };
            return self.emit_trust_query(SUB_CONFIG_TRUST_STATUS, target, network, 0, now_ms);
        }
        // The object assembled — NOT a config verdict. Read the operation's
        // real status with a follow-up StatusQuery on the same operation_id.
        let Some(pending) = self.pending.take() else {
            return ConfigStep::Done(ConfigOutcome::PermitAssembled(None));
        };
        self.emit_status(
            pending.target,
            pending.config_namespace,
            pending.operation_id,
            now_ms,
        )
    }

    /// Consume a 0x26/0x27 reply: the body must decode under the endpoint
    /// codec, echo the emitted nonce, and name the queried network (and
    /// namespace for 0x27) — anything else is a protocol fault. A body
    /// that passes is reported verbatim: the install receipt (0x26) or
    /// the RCR2 baseline evidence (0x27).
    #[allow(clippy::too_many_arguments)]
    fn on_trust_query_reply<C: ConfigAuthorityLedger>(
        &mut self,
        commit: &mut C,
        sub: u8,
        inner: &[u8],
        target: u64,
        config_namespace: u16,
        network: u64,
        nonce: [u8; 16],
        now_ms: u64,
    ) -> ConfigStep {
        let reply = match host_ops::decode_config_reply(inner, sub) {
            Ok(reply) => reply,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if reply.target != target {
            self.clear_issue();
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let result = match ConfigOpsResult::try_from_u16(reply.result) {
            Ok(result) => result,
            Err(_) => {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if result != ConfigOpsResult::Ok {
            self.clear_issue();
            return ConfigStep::Done(map_refusal(result, None));
        }
        if sub == SUB_CONFIG_RECOVERY_INFO {
            let info = match recovery_info_decode(&reply.body) {
                Ok(info) => info,
                Err(_) => {
                    self.clear_issue();
                    return ConfigStep::Done(ConfigOutcome::ProtocolError);
                }
            };
            if info.nonce_echo != nonce
                || info.network != network
                || info.config_namespace != config_namespace
            {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
            if let Some(recover) = self.recover.take() {
                if info.recovery_version != RCR2_VERSION
                    || info.profile_bits & (1_u32 << self.issuer.profile()) == 0
                {
                    return ConfigStep::Done(ConfigOutcome::RefusedProfile);
                }
                if info.schema != recover.schema
                    || info.flags & RECOVERY_INFO_FLAG_IMPAIRED == 0
                    || info.store_floor >= u32::MAX - 1
                    || info.decision_floor == u64::MAX
                    || recover.new_store_generation != info.store_floor + 1
                    || recover.new_revision != info.decision_floor + 1
                    || (recover.mode != RCR2_MODE_REPROVISION
                        && (info.flags & RECOVERY_INFO_FLAG_SURVIVOR_KNOWN == 0
                            || recover.snapshot_hash != info.snapshot_hash))
                {
                    return ConfigStep::Done(ConfigOutcome::RefusedStale);
                }
                self.submit_recover(
                    commit,
                    recover.target,
                    recover.config_namespace,
                    recover.schema,
                    recover.mode,
                    recover.new_store_generation,
                    recover.new_revision,
                    recover.snapshot_hash,
                    &recover.baseline,
                    now_ms,
                )
            } else if let Some(propose) = self.propose.as_ref() {
                if info.schema != propose.schema || info.flags & RECOVERY_INFO_FLAG_IMPAIRED != 0 {
                    self.clear_issue();
                    return ConfigStep::Done(ConfigOutcome::RefusedStale);
                }
                if info.profile_bits & (1_u32 << self.issuer.profile()) == 0 {
                    self.clear_issue();
                    return ConfigStep::Done(ConfigOutcome::RefusedProfile);
                }
                self.emit_challenge(target, config_namespace, info.schema, now_ms)
            } else {
                self.clear_issue();
                ConfigStep::Done(ConfigOutcome::RecoveryInfo(info))
            }
        } else {
            let status = match trust_status_decode(&reply.body) {
                Ok(status) => status,
                Err(_) => {
                    self.clear_issue();
                    return ConfigStep::Done(ConfigOutcome::ProtocolError);
                }
            };
            if status.nonce_echo != nonce || status.network != network {
                self.clear_issue();
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
            self.clear_issue();
            ConfigStep::Done(ConfigOutcome::TrustStatus(status))
        }
    }

    fn on_status_reply<C: ConfigAuthorityLedger>(
        &mut self,
        commit: &mut C,
        inner: &[u8],
        target: u64,
        config_namespace: u16,
        operation_id: [u8; 16],
        _now_ms: u64,
    ) -> ConfigStep {
        self.clear_issue();
        let reply = match host_ops::decode_config_reply(inner, SUB_CONFIG_STATUS) {
            Ok(reply) => reply,
            Err(_) => return ConfigStep::Done(ConfigOutcome::ProtocolError),
        };
        if reply.target != target {
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let result = match ConfigOpsResult::try_from_u16(reply.result) {
            Ok(result) => result,
            Err(_) => return ConfigStep::Done(ConfigOutcome::ProtocolError),
        };
        if result != ConfigOpsResult::Ok {
            return ConfigStep::Done(map_refusal(result, Some(operation_id)));
        }
        let status = match control_status_decode(&reply.body) {
            Ok(status) => status,
            Err(_) => return ConfigStep::Done(ConfigOutcome::ProtocolError),
        };
        // The body must answer THIS query — the queried operation_id and
        // namespace echo. A status bound to a different operation would
        // report a verdict for work we did not ask about.
        if status.config_namespace != config_namespace || status.operation_id != operation_id {
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        if matches!(status.phase, ConfigPhase::Active | ConfigPhase::Interrupted)
            && status.reason != routeloom_wire::endpoint::ConfigReason::InProgress
        {
            let _ = commit.issue_complete(&operation_id);
        }
        ConfigStep::Done(ConfigOutcome::Statused(status))
    }
}

fn map_refusal(result: ConfigOpsResult, operation_id: Option<[u8; 16]>) -> ConfigOutcome {
    match result {
        ConfigOpsResult::Timeout => ConfigOutcome::Timeout,
        ConfigOpsResult::Indeterminate => ConfigOutcome::Indeterminate(operation_id),
        other => ConfigOutcome::Refused(other),
    }
}

/// Issuer-side faults are client faults, not wire faults: an invalid or
/// oversize input is the same refusal the endpoint codec would emit
/// (Invalid), a CAS mismatch names a stale base snapshot distinctly so
/// the caller can re-read and retry, and an unoffered profile refuses
/// distinctly (never a fallback cue) — none of them is a ProtocolError,
/// which the wire reserves for malformed/mismatched replies.
fn map_issue_error(error: ConfigError) -> ConfigOutcome {
    match error {
        ConfigError::Expired => ConfigOutcome::Timeout,
        ConfigError::Stale => ConfigOutcome::RefusedStale,
        ConfigError::Unsupported => ConfigOutcome::RefusedProfile,
        ConfigError::InvalidArgument | ConfigError::Malformed | ConfigError::TooLarge => {
            ConfigOutcome::Refused(ConfigOpsResult::Invalid)
        }
        _ => ConfigOutcome::ProtocolError,
    }
}

/// Ledger-side refusals: an unprovable commit (fault, exhaustion, or a
/// torn entry) is Indeterminate — the lane never transmits what the
/// store did not prove — while a rotated identity, an op conflict, or
/// a recovery on a memory store refuses honestly without sending.
fn map_issue_refusal(refusal: IssueRefusal) -> ConfigOutcome {
    match refusal {
        IssueRefusal::Unprovable => ConfigOutcome::Indeterminate(None),
        IssueRefusal::IdentityChanged => ConfigOutcome::Refused(ConfigOpsResult::Denied),
        IssueRefusal::OpConflict => ConfigOutcome::Refused(ConfigOpsResult::Invalid),
        IssueRefusal::RecoveryNeedsDurable => ConfigOutcome::Refused(ConfigOpsResult::Unsupported),
        IssueRefusal::Capacity => ConfigOutcome::Refused(ConfigOpsResult::Busy),
    }
}

/// SHA256(domain_snapshot || namespace u16 || schema u16 || snapshot_tlv) —
/// the §5.4 snapshot hash the command's base/next hash fields carry.
fn snapshot_hash(
    config_namespace: u16,
    schema: u16,
    snapshot_tlv: &[u8],
) -> Result<[u8; 32], ConfigError> {
    // Reject a structurally-invalid snapshot early so a malformed base can
    // never be hashed into a command.
    config_tlv_decode(snapshot_tlv).map_err(|_| ConfigError::Malformed)?;
    let input = config_snapshot_hash_input(config_namespace, schema, snapshot_tlv)
        .map_err(|_| ConfigError::InvalidArgument)?;
    Ok(sha256(&input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_wire::endpoint::{config_tlv_encode, ConfigFieldType};

    const DEV_KEY: &[u8] = b"dev-config-key-0123456789abcdef";

    fn hex_lower(bytes: &[u8]) -> String {
        crate::receive_log::hex_lower(bytes)
    }

    fn field(id: u16, ty: ConfigFieldType, value: &[u8]) -> ConfigField {
        ConfigField {
            field_id: id,
            field_type: ty,
            value: value.to_vec(),
        }
    }

    // A challenge whose active_hash commits to `base_snapshot` under
    // (ns, schema) — the CAS input the issuer checks.
    fn challenge(ns: u16, schema: u16, base_snapshot: &[u8], revision: u64) -> ControlChallenge {
        ControlChallenge {
            config_namespace: ns,
            schema,
            client_nonce: [0xC1; 16],
            target_boot: 7,
            challenge_nonce: [0xD2; 16],
            revision,
            active_hash: snapshot_hash(ns, schema, base_snapshot).unwrap(),
            valid_for_ms: 30_000,
        }
    }

    #[test]
    fn hmac_sha256_matches_rfc4231() {
        // RFC 4231 test case 1: key = 20 x 0x0b, data = "Hi There".
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex_lower(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Case 2: key = "Jefe", data = "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex_lower(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn permit_aad_layout_is_fixed() {
        // aad = domain(27 incl. NUL) || network8 || target8 || ns2 = 45 B.
        let aad = config_permit_aad(0x0102_0304_0506_0708, 0x1122_3344_5566_7788, 1).unwrap();
        assert_eq!(aad.len(), 45);
        assert_eq!(&aad[..27], b"RouteLoom/config-permit/v1\0");
        assert_eq!(&aad[27..35], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&aad[35..43], &0x1122_3344_5566_7788_u64.to_be_bytes());
        assert_eq!(&aad[43..45], &1_u16.to_be_bytes());
    }

    #[test]
    fn signed_permit_round_trips_and_tamper_rejected() {
        let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let ch = challenge(1, 1, &base, 4);
        issuer.note_challenge(&ch, 0x99, 1_000).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let outcome = issuer
            .prepare_propose(0x99, 1, 1, &base, &patch, 0, 2_000, 1, 9, [0x5A; 16])
            .unwrap();
        let ProposeOutcome::Draft(draft) = outcome else {
            panic!("expected draft");
        };
        let issued = issuer.sign_permit(&draft, 9).unwrap();
        assert_eq!(issued.kind, ISSUE_KIND_PERMIT);
        assert_eq!(issued.profile, ISSUE_PROFILE_DEV);
        assert_eq!(issued.authority_sequence, 9);
        // Envelope is aad(45) || canonical || tag(16).
        assert_eq!(
            issued.object.len(),
            CONFIG_PERMIT_AAD_SIZE + issued.canonical.len() + CONFIG_DEV_PERMIT_TAG_SIZE
        );
        assert_eq!(&issued.object[..27], b"RouteLoom/config-permit/v1\0");
        // Verify authenticates and returns the same canonical bytes.
        let recovered =
            dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &issued.object).unwrap();
        assert_eq!(recovered, issued.canonical);
        // Tamper anywhere and verification denies.
        for pos in [0, 26, 40, issued.object.len() - 1, issued.object.len() / 2] {
            let mut bad = issued.object.clone();
            bad[pos] ^= 0x01;
            assert!(dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &bad).is_err());
        }
        // Wrong dev key denies.
        assert!(dev_permit_verify(b"other", 0xAAAA, 0x99, 1, 0x42, 1, &issued.object).is_err());
        // Wrong authority / generation deny.
        assert!(dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x43, 1, &issued.object).is_err());
        assert!(dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 2, &issued.object).is_err());
    }

    #[test]
    fn propose_binds_cas_and_revision() {
        let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let ch = challenge(1, 1, &base, 4);
        issuer.note_challenge(&ch, 0x99, 1_000).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let draft = match issuer
            .prepare_propose(0x99, 1, 1, &base, &patch, 0, 2_000, 1, 9, [0x5A; 16])
            .unwrap()
        {
            ProposeOutcome::Draft(p) => p,
            _ => panic!("expected draft"),
        };
        let command = routeloom_wire::endpoint::config_command_decode(&draft.canonical).unwrap();
        assert_eq!(command.expected_revision, 4);
        assert_eq!(command.next_revision, 5);
        assert_eq!(command.base_snapshot_hash, ch.active_hash);
        assert_eq!(command.challenge_nonce, ch.challenge_nonce);
        assert_eq!(command.target_boot, ch.target_boot);
        assert_eq!(command.authority, 0x42);
        assert_eq!(command.authority_sequence, 9);
        // next hash commits to the merged snapshot.
        let next = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[2])]).unwrap();
        assert_eq!(
            command.next_snapshot_hash,
            snapshot_hash(1, 1, &next).unwrap()
        );
    }

    #[test]
    fn propose_no_change_and_stale_and_expired() {
        let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let ch = challenge(1, 1, &base, 4);
        issuer.note_challenge(&ch, 0x99, 1_000).unwrap();
        // A patch that produces no delta -> NoChange, no revision consumed.
        let noop = vec![field(1, ConfigFieldType::U8, &[1])];
        assert_eq!(
            issuer.prepare_propose(0x99, 1, 1, &base, &noop, 0, 2_000, 1, 9, [0x5A; 16]),
            Ok(ProposeOutcome::NoChange)
        );
        // A base snapshot that does not match the challenge hash -> Stale.
        let wrong_base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[9])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        assert_eq!(
            issuer.prepare_propose(0x99, 1, 1, &wrong_base, &patch, 0, 2_000, 1, 9, [0x5A; 16]),
            Err(ConfigError::Stale)
        );
        // Missing challenge -> ChallengeMissing.
        assert_eq!(
            issuer.prepare_propose(0x77, 1, 1, &base, &patch, 0, 2_000, 1, 9, [0x5A; 16]),
            Err(ConfigError::ChallengeMissing)
        );
        // Clock regressed -> ClockUncertain.
        assert_eq!(
            issuer.prepare_propose(0x99, 1, 1, &base, &patch, 0, 500, 1, 9, [0x5A; 16]),
            Err(ConfigError::ClockUncertain)
        );
        // Budget exhausted (now far past valid_for) -> Expired.
        assert_eq!(
            issuer.prepare_propose(
                0x99,
                1,
                1,
                &base,
                &patch,
                0,
                1_000 + 30_000,
                1,
                9,
                [0x5A; 16]
            ),
            Err(ConfigError::Expired)
        );
    }

    // --- ConfigLane ---------------------------------------------------------

    use routeloom_wire::autonomy::EncodedPayload;
    use routeloom_wire::endpoint::{
        control_challenge_encode, control_status_encode, ConfigPhase, ConfigReason,
        RCR2_MODE_REPROVISION,
    };

    fn lane_entropy() -> EntropyFn {
        let mut counter = 0_u8;
        Box::new(move |out: &mut [u8]| {
            counter = counter.wrapping_add(1);
            for b in out.iter_mut() {
                *b = counter;
            }
        })
    }

    fn make_lane() -> ConfigLane {
        let issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        ConfigLane::new(issuer, 1, lane_entropy())
    }

    fn challenge_reply(target: u64, ch: &ControlChallenge) -> Vec<u8> {
        let mut body = EncodedPayload::default();
        control_challenge_encode(ch, &mut body).unwrap();
        host_ops::encode_config_reply(
            SUB_CONFIG_CHALLENGE,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target,
                body: body.view().to_vec(),
            },
        )
        .unwrap()
    }

    fn status_reply(target: u64, status: &ControlStatus) -> Vec<u8> {
        let mut body = EncodedPayload::default();
        control_status_encode(status, &mut body).unwrap();
        host_ops::encode_config_reply(
            SUB_CONFIG_STATUS,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target,
                body: body.view().to_vec(),
            },
        )
        .unwrap()
    }

    fn emit(step: ConfigStep) -> (u64, Vec<u8>) {
        match step {
            ConfigStep::Emit { request, body } => (request, body),
            other => panic!("expected emit, got {other:?}"),
        }
    }

    /// The client_nonce the lane stamped on a challenge emit — the value a
    /// reply's ControlChallenge body must echo back to be accepted.
    fn emitted_nonce(body: &[u8]) -> [u8; 16] {
        host_ops::decode_config_challenge(body)
            .unwrap()
            .client_nonce
    }

    fn done(step: ConfigStep) -> ConfigOutcome {
        match step {
            ConfigStep::Done(outcome) => outcome,
            other => panic!("expected done, got {other:?}"),
        }
    }

    fn control_status(op_id: [u8; 16]) -> ControlStatus {
        ControlStatus {
            config_namespace: 1,
            operation_id: op_id,
            decision_revision: 5,
            active_revision: 5,
            phase: ConfigPhase::Active,
            reason: ConfigReason::Ok,
            active_hash: [0x33; 32],
        }
    }

    #[test]
    fn lane_drives_challenge_then_permit_then_status() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let (req1, body1) = start_propose_challenge(
            &mut lane,
            &mut commit,
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            1_000,
        );
        // The first emit is a ConfigChallenge request (0x23).
        assert_eq!(body1[1], SUB_CONFIG_CHALLENGE);
        assert!(lane.busy());
        // The device answers with a ControlChallenge bound to the base hash
        // and echoing the query's client_nonce.
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        let (req2, body2) =
            emit(lane.on_reply(&mut commit, req1, &challenge_reply(0x99, &ch), 1_100));
        // Next emit is the ConfigPermit transfer (0x21).
        assert_eq!(body2[1], SUB_CONFIG_PERMIT);
        // The device acks the object assembly (0x21 Ok, empty body).
        let ack = host_ops::encode_config_reply(
            SUB_CONFIG_PERMIT,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target: 0x99,
                body: Vec::new(),
            },
        )
        .unwrap();
        let (req3, body3) = emit(lane.on_reply(&mut commit, req2, &ack, 1_200));
        // Object assembled -> the lane follows with a StatusQuery (0x20).
        assert_eq!(body3[1], host_ops::SUB_CONFIG_QUERY);
        // The terminal verdict arrives as a ControlStatus body echoing the
        // operation_id the StatusQuery carried.
        let op = host_ops::decode_config_query(&body3).unwrap().operation_id;
        let outcome = done(lane.on_reply(
            &mut commit,
            req3,
            &status_reply(0x99, &control_status(op)),
            1_300,
        ));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status(op)));
        assert!(!lane.busy());
    }

    #[test]
    fn lane_standalone_challenge_and_status() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        // Standalone challenge.
        let (req, body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        assert_eq!(body[1], SUB_CONFIG_CHALLENGE);
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body);
        let outcome = done(lane.on_reply(&mut commit, req, &challenge_reply(0x99, &ch), 1_100));
        assert_eq!(outcome, ConfigOutcome::Challenged(ch));
        // Standalone status lookup by operation id.
        let (req, body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Status {
                target: 0x99,
                config_namespace: 1,
                operation_id: [0x7B; 16],
            },
            2_000,
        ));
        assert_eq!(body[1], host_ops::SUB_CONFIG_QUERY);
        let outcome = done(lane.on_reply(
            &mut commit,
            req,
            &status_reply(0x99, &control_status([0x7B; 16])),
            2_100,
        ));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status([0x7B; 16])));
    }

    #[test]
    fn lane_reports_timeout_and_indeterminate() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        // A challenge that is never answered -> Timeout at the query deadline.
        let (_req, _body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        assert_eq!(lane.poll(1_000 + CONFIG_QUERY_TIMEOUT_MS - 1), None);
        assert_eq!(
            lane.poll(1_000 + CONFIG_QUERY_TIMEOUT_MS),
            Some(ConfigOutcome::Timeout)
        );
        assert!(!lane.busy());
        // A permit transfer that is never acked -> Indeterminate (the object
        // may have assembled without the ack reaching us), carrying the
        // issued operation_id so the caller can keep querying it.
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let (req1, body1) = start_propose_challenge(
            &mut lane,
            &mut commit,
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            2_000,
        );
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        let (_req2, _b2) =
            emit(lane.on_reply(&mut commit, req1, &challenge_reply(0x99, &ch), 2_100));
        // The propose's operation_id was the lane's second entropy draw
        // (the standalone challenge above consumed the first).
        assert_eq!(
            lane.poll(2_100 + CONFIG_PERMIT_TIMEOUT_MS),
            Some(ConfigOutcome::Indeterminate(Some([0x02; 16])))
        );
    }

    #[test]
    fn lane_reports_refusals_and_dropped() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (_req, _body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        // A second submit while busy is refused Busy, and the in-flight is kept.
        let refused = done(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_010,
        ));
        assert_eq!(refused, ConfigOutcome::Refused(ConfigOpsResult::Busy));
        assert!(lane.busy());
        // A device Busy reply maps to a refusal, not a success.
        let busy = host_ops::encode_config_reply(
            SUB_CONFIG_CHALLENGE,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Busy as u16,
                target: 0x99,
                body: Vec::new(),
            },
        )
        .unwrap();
        // The in-flight request id is the first one (lane kept it).
        let outcome = done(lane.on_reply(&mut commit, 1, &busy, 1_020));
        assert_eq!(outcome, ConfigOutcome::Refused(ConfigOpsResult::Busy));
        // A dropped outbound frame resolves the request, not a silent retry.
        let (req, _b) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Status {
                target: 0x99,
                config_namespace: 1,
                operation_id: [0x01; 16],
            },
            2_000,
        ));
        assert_eq!(
            lane.on_dropped(req),
            ConfigStep::Done(ConfigOutcome::Timeout)
        );
        assert!(!lane.busy());
    }

    #[test]
    fn lane_no_change_short_circuits() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        // Patch identical to base -> NO_CHANGE before any permit is sent.
        let patch = vec![field(1, ConfigFieldType::U8, &[1])];
        let (req1, body1) = start_propose_challenge(
            &mut lane,
            &mut commit,
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            1_000,
        );
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        let outcome = done(lane.on_reply(&mut commit, req1, &challenge_reply(0x99, &ch), 1_100));
        assert_eq!(outcome, ConfigOutcome::NoChange);
        assert!(!lane.busy());
    }

    #[test]
    fn challenge_reply_must_echo_the_emitted_query() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let (req, body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body);
        // A different client_nonce than the query emitted: the body may
        // decode cleanly and still not answer THIS query — ProtocolError,
        // never a Challenged verdict and never a ledger seed.
        let mut foreign = ch.clone();
        foreign.client_nonce = [0xEE; 16];
        assert_eq!(
            done(lane.on_reply(&mut commit, req, &challenge_reply(0x99, &foreign), 1_100)),
            ConfigOutcome::ProtocolError
        );
        assert!(!lane.busy());
        // A mismatched namespace or schema is the same torn exchange.
        for (ns, schema) in [(2_u16, 1_u16), (1, 9)] {
            let mut lane = make_lane();
            let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
            let (req, body) = emit(lane.submit(
                &mut commit,
                ConfigRequest::Challenge {
                    target: 0x99,
                    config_namespace: ns,
                    schema,
                },
                1_000,
            ));
            // The reply claims to answer the query but binds a different
            // namespace/schema pair than the request carried.
            let mut ch = challenge(
                if ns == 2 { 1 } else { ns },
                if ns == 2 { schema } else { 1 },
                &base,
                4,
            );
            ch.client_nonce = emitted_nonce(&body);
            assert_eq!(
                done(lane.on_reply(&mut commit, req, &challenge_reply(0x99, &ch), 1_100)),
                ConfigOutcome::ProtocolError
            );
        }
        // A reply naming a different target is equally foreign.
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (req, body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body);
        assert_eq!(
            done(lane.on_reply(&mut commit, req, &challenge_reply(0x77, &ch), 1_100)),
            ConfigOutcome::ProtocolError
        );
        // And the echo-bound happy path still resolves Challenged.
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (req, body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body);
        assert_eq!(
            done(lane.on_reply(&mut commit, req, &challenge_reply(0x99, &ch), 1_100)),
            ConfigOutcome::Challenged(ch)
        );
    }

    #[test]
    fn status_reply_must_echo_the_queried_operation() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (req, _body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Status {
                target: 0x99,
                config_namespace: 1,
                operation_id: [0x7B; 16],
            },
            1_000,
        ));
        // A well-formed status body for a DIFFERENT operation id: it
        // decodes, it even reports Active — and it is not our query's
        // verdict.
        assert_eq!(
            done(lane.on_reply(
                &mut commit,
                req,
                &status_reply(0x99, &control_status([0x7C; 16])),
                1_100
            )),
            ConfigOutcome::ProtocolError
        );
        assert!(!lane.busy());
        // Same for a foreign namespace or target.
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (req, _body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Status {
                target: 0x99,
                config_namespace: 1,
                operation_id: [0x7B; 16],
            },
            1_000,
        ));
        let mut foreign_ns = control_status([0x7B; 16]);
        foreign_ns.config_namespace = 0x8000;
        assert_eq!(
            done(lane.on_reply(&mut commit, req, &status_reply(0x99, &foreign_ns), 1_100)),
            ConfigOutcome::ProtocolError
        );
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (req, _body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Status {
                target: 0x99,
                config_namespace: 1,
                operation_id: [0x7B; 16],
            },
            1_000,
        ));
        assert_eq!(
            done(lane.on_reply(
                &mut commit,
                req,
                &status_reply(0x77, &control_status([0x7B; 16])),
                1_100
            )),
            ConfigOutcome::ProtocolError
        );
    }

    #[test]
    fn mismatched_lane_reply_clears_the_in_flight_step() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (req, _body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        assert!(lane.busy());
        // A reply naming a lane id that is not in flight resolves the op
        // ProtocolError AND frees the lane — it must not stay armed behind
        // an op that already resolved.
        assert_ne!(req, 999);
        assert_eq!(
            lane.on_reply(&mut commit, 999, &[1, SUB_CONFIG_CHALLENGE, 0, 0], 1_020),
            ConfigStep::Done(ConfigOutcome::ProtocolError)
        );
        assert!(!lane.busy());
        // Same rule for a drop notification naming a different lane id.
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (req, _body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        assert_ne!(req, 999);
        assert_eq!(
            lane.on_dropped(999),
            ConfigStep::Done(ConfigOutcome::ProtocolError)
        );
        assert!(!lane.busy());
    }

    #[test]
    fn refused_note_challenge_evicts_the_cached_record() {
        let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let ch = challenge(1, 1, &base, 4);
        issuer.note_challenge(&ch, 0x99, 1_000).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        // A refused challenge note must evict the cached record: without
        // eviction a later propose would sign the stale nonce/revision.
        let mut bad = ch.clone();
        bad.target_boot = 0; // nonzero-boot invariant — decode would refuse too
        assert_eq!(
            issuer.note_challenge(&bad, 0x99, 2_000),
            Err(ConfigError::InvalidArgument)
        );
        assert_eq!(
            issuer.prepare_propose(0x99, 1, 1, &base, &patch, 0, 2_100, 1, 9, [0x5A; 16]),
            Err(ConfigError::ChallengeMissing)
        );
    }

    #[test]
    fn client_faults_map_to_honest_refusals() {
        // Invalid/oversize/malformed client inputs are the same refusal the
        // endpoint codec emits; a CAS mismatch names a stale base distinctly.
        assert_eq!(
            map_issue_error(ConfigError::InvalidArgument),
            ConfigOutcome::Refused(ConfigOpsResult::Invalid)
        );
        assert_eq!(
            map_issue_error(ConfigError::TooLarge),
            ConfigOutcome::Refused(ConfigOpsResult::Invalid)
        );
        assert_eq!(
            map_issue_error(ConfigError::Malformed),
            ConfigOutcome::Refused(ConfigOpsResult::Invalid)
        );
        assert_eq!(
            map_issue_error(ConfigError::Stale),
            ConfigOutcome::RefusedStale
        );
        // A stale base snapshot through the full lane resolves RefusedStale —
        // the client may re-read the challenge and retry, never a wire fault.
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let wrong_base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[9])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let (req1, body1) = start_propose_challenge(
            &mut lane,
            &mut commit,
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: wrong_base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            1_000,
        );
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        assert_eq!(
            done(lane.on_reply(&mut commit, req1, &challenge_reply(0x99, &ch), 1_100)),
            ConfigOutcome::RefusedStale
        );
        assert!(!lane.busy());
    }

    // --- Step-6 issuance pipeline: RCR2 envelopes, profile signers, ------- //
    // --- durable outbox (design-51 §7.2, T07/T09 cores). ------------------ //

    /// Counts ledger touches: proves a refusal precedes every commit.
    struct CountingCommit {
        inner: crate::send_store::MemoryOperationStore,
        reserves: usize,
        binds: usize,
        signed: usize,
    }

    impl CountingCommit {
        fn fresh() -> Self {
            Self {
                inner: crate::send_store::MemoryOperationStore::new([0xC0; 16]),
                reserves: 0,
                binds: 0,
                signed: 0,
            }
        }

        fn touched(&self) -> bool {
            self.reserves + self.binds + self.signed > 0
        }
    }

    impl crate::send_store::ConfigAuthorityLedger for CountingCommit {
        fn issue_reserve(
            &mut self,
            identity: &crate::send_store::IssueIdentity,
        ) -> Result<u64, crate::send_store::IssueRefusal> {
            self.reserves += 1;
            self.inner.issue_reserve(identity)
        }

        fn issue_bind(
            &mut self,
            op_id: &[u8; 16],
            canonical: &[u8],
        ) -> Result<(), crate::send_store::IssueRefusal> {
            self.binds += 1;
            self.inner.issue_bind(op_id, canonical)
        }

        fn issue_signed(
            &mut self,
            op_id: &[u8; 16],
            signed: &[u8],
        ) -> Result<(), crate::send_store::IssueRefusal> {
            self.signed += 1;
            self.inner.issue_signed(op_id, signed)
        }

        fn issue_original(&mut self, op_id: &[u8; 16]) -> Option<(Vec<u8>, Vec<u8>)> {
            self.inner.issue_original(op_id)
        }

        fn issue_complete(
            &mut self,
            op_id: &[u8; 16],
        ) -> Result<(), crate::send_store::IssueRefusal> {
            self.inner.issue_complete(op_id)
        }
    }

    /// Unique scratch SQLite store per test; files are removed on drop.
    struct TempDb {
        path: std::path::PathBuf,
    }

    impl TempDb {
        fn open(name: &str) -> (Self, crate::sqlite_store::SqliteOperationStore) {
            let path = std::env::temp_dir()
                .join(format!("routeloom-cfg51-{}-{name}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let store = crate::sqlite_store::SqliteOperationStore::open(&path).unwrap();
            (Self { path }, store)
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = self.path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let _ = std::fs::remove_file(sidecar);
            }
        }
    }

    /// Fixed COSE authority key for tests — deterministic, never the dev
    /// HMAC key, never a root key.
    fn cose_signer() -> routeloom_provision::signer::FileAuthoritySigner {
        routeloom_provision::signer::FileAuthoritySigner::from_secret(0x42, &[0x5E; 32]).unwrap()
    }

    fn recover_request() -> ConfigRequest {
        ConfigRequest::Recover {
            target: 0x99,
            config_namespace: 1,
            schema: 1,
            mode: 0,
            new_store_generation: 4,
            new_revision: 8,
            snapshot_hash: [0xAB; 32],
            baseline: Vec::new(),
        }
    }

    fn transfer_ack(sub: u8, target: u64) -> Vec<u8> {
        host_ops::encode_config_reply(
            sub,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target,
                body: Vec::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn recovery_aad_and_envelope_layout_are_fixed() {
        // recovery_aad = 27 + NUL + network u64 + target u64 + ns u16.
        let aad = config_recovery_aad(0xAAAA, 0x99, 1).unwrap();
        assert_eq!(aad.len(), CONFIG_RECOVERY_AAD_SIZE);
        assert_eq!(CONFIG_RECOVERY_AAD_SIZE, 46);
        assert_eq!(&aad[..28], b"RouteLoom/config-recover/v2\0");
        assert_eq!(&aad[28..36], &0xAAAA_u64.to_be_bytes());
        assert_eq!(&aad[36..44], &0x99_u64.to_be_bytes());
        assert_eq!(&aad[44..46], &1_u16.to_be_bytes());
        // The recovery input domain differs from the permit's in both
        // halves, so kind-3 and kind-4 envelopes never verify cross-kind.
        assert_ne!(CONFIG_RECOVERY_DOMAIN, CONFIG_PERMIT_DOMAIN);
        assert_ne!(CONFIG_DEV_RECOVERY_DOMAIN, CONFIG_DEV_PERMIT_DOMAIN);
    }

    #[test]
    fn signed_recovery_round_trips_and_rejects_tamper() {
        let issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        let snapshot = config_tlv_encode(&[field(9, ConfigFieldType::U8, &[3])]).unwrap();
        // An oversize-but-wellformed baseline: six 96-byte blobs.
        let mut big = Vec::new();
        for id in 0..6_u16 {
            big.extend_from_slice(
                &config_tlv_encode(&[field(id, ConfigFieldType::Bytes, &[id as u8; 96])]).unwrap(),
            );
        }
        assert!(big.len() > 512);
        for (mode, baseline) in [(0_u8, Vec::new()), (1, snapshot)] {
            let hash = if mode == RCR2_MODE_REPROVISION {
                snapshot_hash(1, 1, &baseline).unwrap()
            } else {
                [0xAB; 32]
            };
            let (intent, canonical) = issuer
                .prepare_recovery(0x99, 1, 1, mode, 4, 8, hash, &baseline, 1, 15, [7; 16])
                .unwrap();
            assert_eq!(intent.mode, mode);
            let issued = issuer.sign_recovery(&intent, &canonical, 15).unwrap();
            assert_eq!(issued.kind, ISSUE_KIND_RECOVERY);
            assert_eq!(issued.profile, ISSUE_PROFILE_DEV);
            assert_eq!(issued.authority_sequence, 15);
            // Envelope is recovery_aad(46) || RCR2 || tag(16).
            assert_eq!(
                issued.object.len(),
                CONFIG_RECOVERY_AAD_SIZE + canonical.len() + CONFIG_DEV_PERMIT_TAG_SIZE
            );
            let recovered =
                dev_recovery_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &issued.object).unwrap();
            assert_eq!(recovered, canonical);
            // Any tamper in any third breaks the tag or the binding.
            for offset in [
                0,
                CONFIG_RECOVERY_AAD_SIZE - 1,
                CONFIG_RECOVERY_AAD_SIZE,
                CONFIG_RECOVERY_AAD_SIZE + canonical.len() - 1,
                issued.object.len() - 1,
            ] {
                let mut tampered = issued.object.clone();
                tampered[offset] ^= 0x01;
                assert!(
                    dev_recovery_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &tampered).is_err(),
                    "tamper at {offset} must fail (mode {mode})"
                );
            }
            // Wrong expected context is Stale, never a silent accept.
            assert!(
                dev_recovery_verify(DEV_KEY, 0xBBBB, 0x99, 1, 0x42, 1, &issued.object).is_err()
            );
            assert!(
                dev_recovery_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x43, 1, &issued.object).is_err()
            );
        }
        // Malformed intents never draft: bad mode, zero/MAX J, MAX R,
        // oversize baseline, non-TLV baseline. (A zero survivor hash
        // still drafts — it cannot match any proven survivor, so the
        // target refuses it honestly; the codec only pins the shape.)
        for (mode, gen, rev, hash, baseline) in [
            (5_u8, 4_u32, 8_u64, [0xAB; 32], Vec::new()),
            (0, 0, 8, [0xAB; 32], Vec::new()),
            (0, u32::MAX, 8, [0xAB; 32], Vec::new()),
            (0, 4, u64::MAX, [0xAB; 32], Vec::new()),
            (1, 4, 8, [0xAB; 32], big),
            (1, 4, 8, [0xAB; 32], vec![9_u8; 64]),
        ] {
            assert!(
                issuer
                    .prepare_recovery(0x99, 1, 1, mode, gen, rev, hash, &baseline, 1, 15, [7; 16])
                    .is_err(),
                "mode={mode} gen={gen} rev={rev} must not draft"
            );
        }
    }

    #[test]
    fn profile_refusal_precedes_any_commit_or_send() {
        // T07 core: every unoffered profile refuses BEFORE any sequence
        // reservation, signature, or mesh send — with a keyless dev
        // profile, a keyless COSE profile, a foreign-authority COSE key,
        // and an unknown profile value.
        let keyless_dev = ConfigIssuer::new(Vec::new(), 0xAAAA, 0x42, 100);
        assert!(!keyless_dev.ready());
        let mut keyless_cose = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        keyless_cose.set_profile(ISSUE_PROFILE_COSE);
        assert!(!keyless_cose.ready());
        let mut foreign_cose = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        foreign_cose.set_profile(ISSUE_PROFILE_COSE);
        foreign_cose.set_cose_signer(
            routeloom_provision::signer::FileAuthoritySigner::from_secret(0x777, &[0x5E; 32])
                .unwrap(),
        );
        assert!(!foreign_cose.ready());
        let mut unknown = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        unknown.set_profile(7);
        assert!(!unknown.ready());

        // Recover submits refuse without touching the ledger at all.
        for issuer in [keyless_dev, keyless_cose, foreign_cose, unknown] {
            let mut lane = ConfigLane::new(issuer, 1, lane_entropy());
            let mut commit = CountingCommit::fresh();
            assert_eq!(
                done(lane.submit(&mut commit, recover_request(), 1_000)),
                ConfigOutcome::RefusedProfile
            );
            assert!(!commit.touched(), "a profile refusal reserves nothing");
            assert!(!lane.busy(), "a profile refusal emits nothing");
        }
        // The no-fallback proof: a present dev key plus a keyless COSE
        // profile still refuses — the dev key is never consulted.
        let mut lane = ConfigLane::new(
            {
                let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
                issuer.set_profile(ISSUE_PROFILE_COSE);
                issuer
            },
            1,
            lane_entropy(),
        );
        let mut commit = CountingCommit::fresh();
        assert_eq!(
            done(lane.submit(&mut commit, recover_request(), 1_000)),
            ConfigOutcome::RefusedProfile
        );
        assert!(!commit.touched());
        // Propose refuses before the challenge even emits.
        let mut keyless = ConfigLane::new(
            ConfigIssuer::new(Vec::new(), 0xAAAA, 0x42, 100),
            1,
            lane_entropy(),
        );
        let mut commit = CountingCommit::fresh();
        assert_eq!(
            done(keyless.submit(
                &mut commit,
                ConfigRequest::Propose {
                    target: 0x99,
                    config_namespace: 1,
                    schema: 1,
                    base_snapshot: Vec::new(),
                    patch: Vec::new(),
                    apply_budget_ms: 0,
                },
                1_000,
            )),
            ConfigOutcome::RefusedProfile
        );
        assert!(!commit.touched());
        assert!(!keyless.busy());
    }

    #[test]
    fn recover_shape_refuses_before_reserving() {
        // Bad RCR2 inputs refuse as Invalid with zero ledger touches —
        // no sequence is spent on an intent the codec rejects.
        let mut lane = make_lane();
        for request in [
            ConfigRequest::Recover {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                mode: 5,
                new_store_generation: 4,
                new_revision: 8,
                snapshot_hash: [0xAB; 32],
                baseline: Vec::new(),
            },
            ConfigRequest::Recover {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                mode: 0,
                new_store_generation: 0,
                new_revision: 8,
                snapshot_hash: [0xAB; 32],
                baseline: Vec::new(),
            },
            ConfigRequest::Recover {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                mode: 1,
                new_store_generation: 4,
                new_revision: 8,
                snapshot_hash: [0xAB; 32],
                baseline: vec![1; 513],
            },
            // A reprovision whose hash is not the carried baseline's
            // refuses too: signing it would waste a reservation, a
            // signature and a transfer on an object the device must
            // reject at restore time.
            ConfigRequest::Recover {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                mode: 1,
                new_store_generation: 4,
                new_revision: 8,
                snapshot_hash: [0xAB; 32],
                baseline: golden_baseline(),
            },
        ] {
            let mut commit = CountingCommit::fresh();
            assert_eq!(
                done(lane.submit(&mut commit, request, 1_000)),
                ConfigOutcome::Refused(ConfigOpsResult::Invalid)
            );
            assert!(!commit.touched());
            assert!(!lane.busy());
        }
    }

    #[test]
    fn recover_lane_drives_transfer_then_status() {
        // The full RCR2 trip on a DURABLE store: target preflight, then
        // reserve → bind → sign → store, then the 0x24 transfer,
        // follows with the status read, and reports the verdict. The
        // outbox original is byte-identical to the transmitted object.
        let (_db, mut commit) = TempDb::open("recover-trip");
        let mut lane = make_lane();
        let (req1, body1) = start_recovery_transfer(&mut lane, &mut commit, 1_000);
        assert_eq!(body1[1], SUB_CONFIG_RECOVER);
        let transfer = host_ops::decode_config_recover(&body1).unwrap();
        assert_eq!(transfer.target, 0x99);
        // The envelope is aad(46) || RCR2 || tag(16) under the dev key.
        assert_eq!(&transfer.object[..28], b"RouteLoom/config-recover/v2\0");
        let (req2, body2) = emit(lane.on_reply(
            &mut commit,
            req1,
            &transfer_ack(SUB_CONFIG_RECOVER, 0x99),
            1_100,
        ));
        assert_eq!(body2[1], host_ops::SUB_CONFIG_QUERY);
        let op = host_ops::decode_config_query(&body2).unwrap().operation_id;
        let outcome = done(lane.on_reply(
            &mut commit,
            req2,
            &status_reply(0x99, &control_status(op)),
            1_200,
        ));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status(op)));
        assert!(!lane.busy());
        // Retransmit-original evidence: the store holds exactly the bytes
        // the transfer carried, canonical and signed.
        let (canonical, signed) = commit.issue_original(&op).expect("stored original");
        assert_eq!(signed, transfer.object);
        let intent = routeloom_wire::endpoint::config_recovery_decode(&canonical).unwrap();
        assert_eq!(intent.mode, 0);
        assert_eq!(intent.new_store_generation, 4);
        assert_eq!(intent.new_revision, 8);
        assert_eq!(intent.operation_id, op);
        assert_eq!(intent.authority_sequence, 1);
        assert_eq!(intent.snapshot_hash, [0xAB; 32]);
    }

    #[test]
    fn recover_refuses_on_a_memory_store() {
        // Recovery issuance needs the durable outbox — a memory-only
        // store refuses honestly instead of claiming durability.
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let (request, body) = emit(lane.submit(&mut commit, recover_request(), 1_000));
        let query = host_ops::decode_config_recovery_info(&body).unwrap();
        let info = RecoveryInfo {
            config_namespace: 1,
            schema: 1,
            nonce_echo: query.nonce,
            network: 0xAAAA,
            store_floor: 3,
            decision_floor: 7,
            flags: RECOVERY_INFO_FLAG_IMPAIRED | RECOVERY_INFO_FLAG_SURVIVOR_KNOWN,
            recovery_version: RCR2_VERSION,
            profile_bits: 1,
            snapshot_hash: [0xAB; 32],
        };
        assert_eq!(
            done(lane.on_reply(
                &mut commit,
                request,
                &recovery_info_reply(0x99, &info),
                1_100
            )),
            ConfigOutcome::Refused(ConfigOpsResult::Unsupported)
        );
        assert!(!lane.busy());
    }

    #[test]
    fn failed_transfer_keeps_the_signed_original() {
        let (_db, mut commit) = TempDb::open("recover-denied-original");
        let mut lane = make_lane();
        let (request, body) = start_recovery_transfer(&mut lane, &mut commit, 1_000);
        let signed = host_ops::decode_config_recover(&body).unwrap().object;
        let denied = host_ops::encode_config_reply(
            SUB_CONFIG_RECOVER,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Denied as u16,
                target: 0x99,
                body: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            done(lane.on_reply(&mut commit, request, &denied, 1_100)),
            ConfigOutcome::Refused(ConfigOpsResult::Denied)
        );
        let canonical = dev_recovery_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &signed).unwrap();
        let op_id = routeloom_wire::endpoint::config_recovery_decode(&canonical)
            .unwrap()
            .operation_id;
        assert_eq!(commit.issue_original(&op_id), Some((canonical, signed)));
        for id in 1..64_u8 {
            let mut filler = [0_u8; 16];
            filler[0] = 0xFE;
            filler[1] = id;
            commit
                .issue_reserve(&IssueIdentity {
                    kind: ISSUE_KIND_PERMIT,
                    op_id: filler,
                    target: 0x99,
                    namespace: 1,
                    profile: ISSUE_PROFILE_DEV,
                    authority: 0x42,
                    generation: 1,
                    network: 0xAAAA,
                })
                .unwrap();
        }
        let mut overflow = [0_u8; 16];
        overflow[0] = 0xFE;
        overflow[1] = 64;
        assert_eq!(
            commit.issue_reserve(&IssueIdentity {
                kind: ISSUE_KIND_PERMIT,
                op_id: overflow,
                target: 0x99,
                namespace: 1,
                profile: ISSUE_PROFILE_DEV,
                authority: 0x42,
                generation: 1,
                network: 0xAAAA,
            }),
            Err(crate::send_store::IssueRefusal::Capacity)
        );
    }

    #[test]
    fn propose_outbox_holds_the_transmitted_original() {
        // T09 core: the permit the lane transmits is byte-identical to
        // the outbox original, and sequences never repeat.
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let (req1, body1) = start_propose_challenge(
            &mut lane,
            &mut commit,
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch: patch.clone(),
                apply_budget_ms: 0,
            },
            1_000,
        );
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        let (req2, body2) =
            emit(lane.on_reply(&mut commit, req1, &challenge_reply(0x99, &ch), 1_100));
        assert_eq!(body2[1], SUB_CONFIG_PERMIT);
        let transfer = host_ops::decode_config_permit(&body2).unwrap();
        let (_req3, body3) = emit(lane.on_reply(
            &mut commit,
            req2,
            &transfer_ack(SUB_CONFIG_PERMIT, 0x99),
            1_200,
        ));
        let op = host_ops::decode_config_query(&body3).unwrap().operation_id;
        let (canonical, signed) = commit.issue_original(&op).expect("stored original");
        assert_eq!(signed, transfer.permit);
        let command = routeloom_wire::endpoint::config_command_decode(&canonical).unwrap();
        assert_eq!(command.authority_sequence, 1);
        assert_eq!(command.operation_id, op);
        // A second issuance advances — never reuses — the sequence.
        lane.on_reply(
            &mut commit,
            _req3,
            &status_reply(0x99, &control_status(op)),
            1_300,
        );
        let (req4, body4) = start_propose_challenge(
            &mut lane,
            &mut commit,
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            2_000,
        );
        let mut ch2 = challenge(1, 1, &base, 4);
        ch2.client_nonce = emitted_nonce(&body4);
        let (_req5, body5) =
            emit(lane.on_reply(&mut commit, req4, &challenge_reply(0x99, &ch2), 2_100));
        let transfer2 = host_ops::decode_config_permit(&body5).unwrap();
        let recovered =
            dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &transfer2.permit).unwrap();
        let command2 = routeloom_wire::endpoint::config_command_decode(&recovered).unwrap();
        assert_eq!(command2.authority_sequence, 2);
    }

    #[test]
    fn cose_issuer_signs_both_kinds_and_self_checks() {
        // T07 COSE leg: the authority signer produces restricted
        // COSE_Sign1 envelopes for RCC1 and RCR2 that parse under the
        // shared profile and verify under the signer's own public half.
        let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        issuer.set_profile(ISSUE_PROFILE_COSE);
        issuer.set_cose_signer(cose_signer());
        assert!(issuer.ready());
        // A permit draft signs (challenge seeded first, as the lane does).
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let ch = challenge(1, 1, &base, 4);
        issuer.note_challenge(&ch, 0x99, 1_000).unwrap();
        let draft = match issuer
            .prepare_propose(
                0x99,
                1,
                1,
                &base,
                &[field(1, ConfigFieldType::U8, &[2])],
                0,
                1_100,
                1,
                9,
                [0x5A; 16],
            )
            .unwrap()
        {
            ProposeOutcome::Draft(draft) => draft,
            _ => panic!("expected draft"),
        };
        let permit = issuer.sign_permit(&draft, 9).unwrap();
        assert_eq!(permit.profile, ISSUE_PROFILE_COSE);
        assert_cose_envelope(&permit.object, &permit.canonical, 0x42, ISSUE_KIND_PERMIT);
        // A recovery intent signs under its own AAD.
        let baseline = config_tlv_encode(&[field(2, ConfigFieldType::U8, &[3])]).unwrap();
        let hash = snapshot_hash(1, 1, &baseline).unwrap();
        let (intent, canonical) = issuer
            .prepare_recovery(0x99, 1, 1, 1, 4, 8, hash, &baseline, 1, 10, [0x6B; 16])
            .unwrap();
        let recovery = issuer.sign_recovery(&intent, &canonical, 10).unwrap();
        assert_eq!(recovery.profile, ISSUE_PROFILE_COSE);
        assert_cose_envelope(
            &recovery.object,
            &recovery.canonical,
            0x42,
            ISSUE_KIND_RECOVERY,
        );
        // The two envelopes differ in AAD but share the profile shape —
        // and neither verifies under the other's AAD.
        assert_ne!(permit.object, recovery.object);
    }

    fn test_manifest() -> Vec<u8> {
        // Structurally valid RTM1 shape (the lane checks the envelope,
        // never the root signature — the target's TrustView does that).
        routeloom_provision::manifest::manifest_assemble(&[7_u8; 64], 0x100, &[9_u8; 64]).unwrap()
    }

    fn trust_status_reply(target: u64, status: &TrustStatus) -> Vec<u8> {
        let mut body = EncodedPayload::default();
        routeloom_wire::endpoint::trust_status_encode(status, &mut body).unwrap();
        host_ops::encode_config_reply(
            SUB_CONFIG_TRUST_STATUS,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target,
                body: body.view().to_vec(),
            },
        )
        .unwrap()
    }

    fn recovery_info_reply(target: u64, info: &RecoveryInfo) -> Vec<u8> {
        let mut body = EncodedPayload::default();
        routeloom_wire::endpoint::recovery_info_encode(info, &mut body).unwrap();
        host_ops::encode_config_reply(
            SUB_CONFIG_RECOVERY_INFO,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target,
                body: body.view().to_vec(),
            },
        )
        .unwrap()
    }

    fn start_propose_challenge<C: crate::send_store::ConfigAuthorityLedger>(
        lane: &mut ConfigLane,
        commit: &mut C,
        request: ConfigRequest,
        now_ms: u64,
    ) -> (u64, Vec<u8>) {
        let (query_id, body) = emit(lane.submit(commit, request, now_ms));
        assert_eq!(body[1], SUB_CONFIG_RECOVERY_INFO);
        let query = host_ops::decode_config_recovery_info(&body).unwrap();
        let info = RecoveryInfo {
            config_namespace: 1,
            schema: 1,
            nonce_echo: query.nonce,
            network: 0xAAAA,
            store_floor: 3,
            decision_floor: 7,
            flags: 0,
            recovery_version: RCR2_VERSION,
            profile_bits: 1_u32 << lane.issuer.profile(),
            snapshot_hash: [0; 32],
        };
        emit(lane.on_reply(
            commit,
            query_id,
            &recovery_info_reply(0x99, &info),
            now_ms + 10,
        ))
    }

    fn start_recovery_transfer<C: crate::send_store::ConfigAuthorityLedger>(
        lane: &mut ConfigLane,
        commit: &mut C,
        now_ms: u64,
    ) -> (u64, Vec<u8>) {
        let (request, body) = emit(lane.submit(commit, recover_request(), now_ms));
        assert_eq!(body[1], SUB_CONFIG_RECOVERY_INFO);
        let query = host_ops::decode_config_recovery_info(&body).unwrap();
        let info = RecoveryInfo {
            config_namespace: 1,
            schema: 1,
            nonce_echo: query.nonce,
            network: 0xAAAA,
            store_floor: 3,
            decision_floor: 7,
            flags: RECOVERY_INFO_FLAG_IMPAIRED | RECOVERY_INFO_FLAG_SURVIVOR_KNOWN,
            recovery_version: RCR2_VERSION,
            profile_bits: 1_u32 << lane.issuer.profile(),
            snapshot_hash: [0xAB; 32],
        };
        emit(lane.on_reply(
            commit,
            request,
            &recovery_info_reply(0x99, &info),
            now_ms + 10,
        ))
    }

    #[test]
    fn recover_checks_target_capability_before_reserving() {
        for case in 0..9 {
            let mut lane = make_lane();
            let mut commit = CountingCommit::fresh();
            let (request, body) = emit(lane.submit(&mut commit, recover_request(), 1_000));
            assert_eq!(body[1], SUB_CONFIG_RECOVERY_INFO);
            assert_eq!(commit.reserves, 0);
            let query = host_ops::decode_config_recovery_info(&body).unwrap();
            let mut info = RecoveryInfo {
                config_namespace: 1,
                schema: 1,
                nonce_echo: query.nonce,
                network: 0xAAAA,
                store_floor: 3,
                decision_floor: 7,
                flags: RECOVERY_INFO_FLAG_IMPAIRED | RECOVERY_INFO_FLAG_SURVIVOR_KNOWN,
                recovery_version: RCR2_VERSION,
                profile_bits: 1,
                snapshot_hash: [0xAB; 32],
            };
            let expected = match case {
                0 => {
                    info.profile_bits = 0;
                    ConfigOutcome::RefusedProfile
                }
                1 => {
                    info.recovery_version = 1;
                    ConfigOutcome::RefusedProfile
                }
                2 => {
                    info.flags = 0;
                    ConfigOutcome::RefusedStale
                }
                3 => {
                    info.store_floor = 4;
                    ConfigOutcome::RefusedStale
                }
                4 => {
                    info.decision_floor = u64::MAX;
                    ConfigOutcome::RefusedStale
                }
                5 => {
                    info.store_floor = u32::MAX - 1;
                    ConfigOutcome::RefusedStale
                }
                6 => {
                    info.flags = RECOVERY_INFO_FLAG_IMPAIRED;
                    ConfigOutcome::RefusedStale
                }
                7 => {
                    info.snapshot_hash[0] ^= 1;
                    ConfigOutcome::RefusedStale
                }
                _ => {
                    info.schema = 2;
                    ConfigOutcome::RefusedStale
                }
            };
            assert_eq!(
                done(lane.on_reply(
                    &mut commit,
                    request,
                    &recovery_info_reply(0x99, &info),
                    1_100
                )),
                expected,
                "case {case}"
            );
            assert_eq!(commit.reserves, 0, "case {case}");
        }
    }

    #[test]
    fn recover_query_timeout_clears_pending_state() {
        let mut lane = make_lane();
        let mut commit = CountingCommit::fresh();
        let (_request, body) = emit(lane.submit(&mut commit, recover_request(), 1_000));
        assert_eq!(body[1], SUB_CONFIG_RECOVERY_INFO);
        assert_eq!(
            lane.poll(1_000 + CONFIG_QUERY_TIMEOUT_MS),
            Some(ConfigOutcome::Timeout)
        );
        assert!(lane.recover.is_none());
        assert_eq!(commit.reserves, 0);
        let (request, body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::RecoveryInfo {
                target: 0x99,
                network: 0xAAAA,
                config_namespace: 1,
            },
            2_000,
        ));
        let query = host_ops::decode_config_recovery_info(&body).unwrap();
        let info = RecoveryInfo {
            config_namespace: 1,
            schema: 1,
            nonce_echo: query.nonce,
            network: 0xAAAA,
            store_floor: 3,
            decision_floor: 7,
            flags: RECOVERY_INFO_FLAG_IMPAIRED | RECOVERY_INFO_FLAG_SURVIVOR_KNOWN,
            recovery_version: RCR2_VERSION,
            profile_bits: 1,
            snapshot_hash: [0xAB; 32],
        };
        assert_eq!(
            done(lane.on_reply(
                &mut commit,
                request,
                &recovery_info_reply(0x99, &info),
                2_100
            )),
            ConfigOutcome::RecoveryInfo(info)
        );
        assert_eq!(commit.reserves, 0);
    }

    #[test]
    fn propose_checks_target_capability_before_reserving() {
        let mut lane = make_lane();
        let mut commit = CountingCommit::fresh();
        let (request, body) = emit(lane.submit(
            &mut commit,
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: Vec::new(),
                patch: vec![field(1, ConfigFieldType::U8, &[1])],
                apply_budget_ms: 0,
            },
            1_000,
        ));
        assert_eq!(body[1], SUB_CONFIG_RECOVERY_INFO);
        assert_eq!(commit.reserves, 0);
        let query = host_ops::decode_config_recovery_info(&body).unwrap();
        let info = RecoveryInfo {
            config_namespace: 1,
            schema: 1,
            nonce_echo: query.nonce,
            network: 0xAAAA,
            store_floor: 1,
            decision_floor: 1,
            flags: 0,
            recovery_version: RCR2_VERSION,
            profile_bits: 0,
            snapshot_hash: [0; 32],
        };
        assert_eq!(
            done(lane.on_reply(
                &mut commit,
                request,
                &recovery_info_reply(0x99, &info),
                1_100
            )),
            ConfigOutcome::RefusedProfile
        );
        assert_eq!(commit.reserves, 0);
    }

    #[test]
    fn trust_install_transfers_then_reads_the_receipt() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        // A malformed envelope refuses before any mesh send.
        assert_eq!(
            done(lane.submit(
                &mut commit,
                ConfigRequest::TrustInstall {
                    target: 0x99,
                    network: 0xAAAA,
                    manifest: vec![0xD2, 0x84],
                },
                1_000,
            )),
            ConfigOutcome::Refused(ConfigOpsResult::Invalid)
        );
        assert!(!lane.busy());
        // The install transfers the manifest verbatim on 0x25.
        let manifest = test_manifest();
        let (req1, body1) = emit(lane.submit(
            &mut commit,
            ConfigRequest::TrustInstall {
                target: 0x99,
                network: 0xAAAA,
                manifest: manifest.clone(),
            },
            1_000,
        ));
        assert_eq!(body1[1], SUB_CONFIG_TRUST);
        let transfer = host_ops::decode_config_trust(&body1).unwrap();
        assert_eq!(transfer.target, 0x99);
        assert_eq!(transfer.manifest, manifest);
        // Assembly is not a verdict: the lane follows with the 0x26
        // receipt read, then reports the TrustStatus body.
        let (req2, body2) = emit(lane.on_reply(
            &mut commit,
            req1,
            &transfer_ack(SUB_CONFIG_TRUST, 0x99),
            1_100,
        ));
        assert_eq!(body2[1], SUB_CONFIG_TRUST_STATUS);
        let query = host_ops::decode_config_trust_status(&body2).unwrap();
        assert_eq!((query.target, query.network), (0x99, 0xAAAA));
        let status = TrustStatus {
            nonce_echo: query.nonce,
            store_epoch: 2,
            min_authority_generation: 3,
            network: 0xAAAA,
            image_fingerprint: [0xF1; 32],
            anchor_count: 1,
            key_count: 2,
            revocation_count: 0,
            flags: 0,
        };
        let outcome =
            done(lane.on_reply(&mut commit, req2, &trust_status_reply(0x99, &status), 1_200));
        assert_eq!(outcome, ConfigOutcome::TrustStatus(status));
        assert!(!lane.busy());
    }

    #[test]
    fn recover_lane_drives_cose_trip_to_a_cose_target() {
        // The §9.3 linkage: the same full RCR2 trip as the dev case,
        // but issued under the COSE profile — the transfer carries a
        // tag-18 COSE_Sign1 envelope (never aad || RCR2 || tag16), and
        // the stored original is byte-identical to it.
        let (_db, mut commit) = TempDb::open("recover-trip-cose");
        let mut lane = ConfigLane::new(
            {
                let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
                issuer.set_profile(ISSUE_PROFILE_COSE);
                issuer.set_cose_signer(cose_signer());
                issuer
            },
            1,
            lane_entropy(),
        );
        let (req1, body1) = start_recovery_transfer(&mut lane, &mut commit, 1_000);
        assert_eq!(body1[1], SUB_CONFIG_RECOVER);
        let transfer = host_ops::decode_config_recover(&body1).unwrap();
        assert_eq!(transfer.target, 0x99);
        assert_eq!(&transfer.object[..2], &[0xD2, 0x84]);
        let (req2, body2) = emit(lane.on_reply(
            &mut commit,
            req1,
            &transfer_ack(SUB_CONFIG_RECOVER, 0x99),
            1_100,
        ));
        assert_eq!(body2[1], host_ops::SUB_CONFIG_QUERY);
        let op = host_ops::decode_config_query(&body2).unwrap().operation_id;
        let outcome = done(lane.on_reply(
            &mut commit,
            req2,
            &status_reply(0x99, &control_status(op)),
            1_200,
        ));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status(op)));
        assert!(!lane.busy());
        let (canonical, signed) = commit.issue_original(&op).expect("stored original");
        assert_eq!(signed, transfer.object);
        let intent = routeloom_wire::endpoint::config_recovery_decode(&canonical).unwrap();
        assert_eq!(intent.mode, 0);
        assert_eq!(intent.new_store_generation, 4);
        assert_eq!(intent.new_revision, 8);
        assert_eq!(intent.authority_generation, 1);
        assert_eq!(intent.authority_sequence, 1);
        assert_eq!(intent.snapshot_hash, [0xAB; 32]);
    }

    /// A ledger that refuses every commit: the authority store stopped
    /// or faulted mid-disaster.
    struct RefusingLedger;

    impl crate::send_store::ConfigAuthorityLedger for RefusingLedger {
        fn issue_reserve(
            &mut self,
            _identity: &crate::send_store::IssueIdentity,
        ) -> Result<u64, crate::send_store::IssueRefusal> {
            Err(crate::send_store::IssueRefusal::Unprovable)
        }

        fn issue_bind(
            &mut self,
            _op_id: &[u8; 16],
            _canonical: &[u8],
        ) -> Result<(), crate::send_store::IssueRefusal> {
            Err(crate::send_store::IssueRefusal::Unprovable)
        }

        fn issue_signed(
            &mut self,
            _op_id: &[u8; 16],
            _signed: &[u8],
        ) -> Result<(), crate::send_store::IssueRefusal> {
            Err(crate::send_store::IssueRefusal::Unprovable)
        }

        fn issue_original(&mut self, _op_id: &[u8; 16]) -> Option<(Vec<u8>, Vec<u8>)> {
            None
        }

        fn issue_complete(
            &mut self,
            _op_id: &[u8; 16],
        ) -> Result<(), crate::send_store::IssueRefusal> {
            Err(crate::send_store::IssueRefusal::Unprovable)
        }
    }

    #[test]
    fn trust_install_transfers_while_the_ledger_is_stopped() {
        // The §9.3 linkage: root delivery takes no ledger at all, so a
        // stopped authority store must not block the rotation a
        // disaster recovery depends on.
        let mut lane = make_lane();
        let mut commit = RefusingLedger;
        let manifest = test_manifest();
        let (req1, body1) = emit(lane.submit(
            &mut commit,
            ConfigRequest::TrustInstall {
                target: 0x99,
                network: 0xAAAA,
                manifest: manifest.clone(),
            },
            1_000,
        ));
        assert_eq!(body1[1], SUB_CONFIG_TRUST);
        let transfer = host_ops::decode_config_trust(&body1).unwrap();
        assert_eq!(transfer.manifest, manifest);
        let (req2, body2) = emit(lane.on_reply(
            &mut commit,
            req1,
            &transfer_ack(SUB_CONFIG_TRUST, 0x99),
            1_100,
        ));
        assert_eq!(body2[1], SUB_CONFIG_TRUST_STATUS);
        let query = host_ops::decode_config_trust_status(&body2).unwrap();
        let status = TrustStatus {
            nonce_echo: query.nonce,
            store_epoch: 2,
            min_authority_generation: 2,
            network: 0xAAAA,
            image_fingerprint: [0xF1; 32],
            anchor_count: 1,
            key_count: 2,
            revocation_count: 0,
            flags: 0,
        };
        let outcome =
            done(lane.on_reply(&mut commit, req2, &trust_status_reply(0x99, &status), 1_200));
        assert_eq!(outcome, ConfigOutcome::TrustStatus(status));
        assert!(!lane.busy());
    }

    #[test]
    fn lane_rebinds_issuance_to_the_recovered_generation() {
        // The host half of T06: after the authority disaster the
        // operator applies the recovered ledger's generation to the
        // lane (the same seam dispatch drives per issuance) over a
        // reprovisioned store lineage, and later objects bind the new
        // generation — while the old lineage refuses to rotate.
        let mut lane = make_lane();
        let (_db, mut commit) = TempDb::open("gen-rebind-1");
        let (req1, body1) = start_recovery_transfer(&mut lane, &mut commit, 1_000);
        assert_eq!(body1[1], SUB_CONFIG_RECOVER);
        let (req2, body2) = emit(lane.on_reply(
            &mut commit,
            req1,
            &transfer_ack(SUB_CONFIG_RECOVER, 0x99),
            1_100,
        ));
        let op1 = host_ops::decode_config_query(&body2).unwrap().operation_id;
        let outcome = done(lane.on_reply(
            &mut commit,
            req2,
            &status_reply(0x99, &control_status(op1)),
            1_200,
        ));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status(op1)));
        let (canonical1, _) = commit.issue_original(&op1).expect("first original");
        let first = routeloom_wire::endpoint::config_recovery_decode(&canonical1).unwrap();
        assert_eq!(first.authority_generation, 1);
        assert_eq!(first.authority_sequence, 1);

        // Disaster + recovery: the new generation over a fresh lineage.
        lane.set_authority(2);
        let (_db2, mut commit2) = TempDb::open("gen-rebind-2");
        let (req3, body3) = start_recovery_transfer(&mut lane, &mut commit2, 2_000);
        assert_eq!(body3[1], SUB_CONFIG_RECOVER);
        let (req4, body4) = emit(lane.on_reply(
            &mut commit2,
            req3,
            &transfer_ack(SUB_CONFIG_RECOVER, 0x99),
            2_100,
        ));
        let op2 = host_ops::decode_config_query(&body4).unwrap().operation_id;
        assert_ne!(op1, op2);
        let outcome = done(lane.on_reply(
            &mut commit2,
            req4,
            &status_reply(0x99, &control_status(op2)),
            2_200,
        ));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status(op2)));
        let (canonical2, _) = commit2.issue_original(&op2).expect("second original");
        let second = routeloom_wire::endpoint::config_recovery_decode(&canonical2).unwrap();
        assert_eq!(second.authority_generation, 2);
        assert_eq!(second.authority_sequence, 1);

        // The old lineage pins generation 1: issuing the recovered
        // generation against it refuses instead of rotating in place.
        let mut lane2 = make_lane();
        lane2.set_authority(2);
        let (request, body) = emit(lane2.submit(&mut commit, recover_request(), 3_000));
        let query = host_ops::decode_config_recovery_info(&body).unwrap();
        let info = RecoveryInfo {
            config_namespace: 1,
            schema: 1,
            nonce_echo: query.nonce,
            network: 0xAAAA,
            store_floor: 3,
            decision_floor: 7,
            flags: RECOVERY_INFO_FLAG_IMPAIRED | RECOVERY_INFO_FLAG_SURVIVOR_KNOWN,
            recovery_version: RCR2_VERSION,
            profile_bits: 1,
            snapshot_hash: [0xAB; 32],
        };
        assert_eq!(
            done(lane2.on_reply(
                &mut commit,
                request,
                &recovery_info_reply(0x99, &info),
                3_100
            )),
            ConfigOutcome::Refused(ConfigOpsResult::Denied)
        );
        assert!(!lane2.busy());
    }

    #[test]
    fn trust_queries_bind_nonce_network_and_namespace() {
        let mut lane = make_lane();
        let mut commit = crate::send_store::MemoryOperationStore::new([0xC0; 16]);
        // Standalone 0x26 read.
        let (req1, body1) = emit(lane.submit(
            &mut commit,
            ConfigRequest::TrustStatus {
                target: 0x99,
                network: 0xAAAA,
            },
            1_000,
        ));
        assert_eq!(body1[1], SUB_CONFIG_TRUST_STATUS);
        let query = host_ops::decode_config_trust_status(&body1).unwrap();
        // A body for another network is a protocol fault, never evidence.
        let mut foreign = TrustStatus {
            nonce_echo: query.nonce,
            store_epoch: 2,
            min_authority_generation: 3,
            network: 0xBBBB,
            image_fingerprint: [0xF1; 32],
            anchor_count: 1,
            key_count: 2,
            revocation_count: 0,
            flags: 0,
        };
        assert_eq!(
            done(lane.on_reply(
                &mut commit,
                req1,
                &trust_status_reply(0x99, &foreign),
                1_100
            )),
            ConfigOutcome::ProtocolError
        );
        // Re-query; a body echoing a foreign nonce faults the same way.
        let (req2, body2) = emit(lane.submit(
            &mut commit,
            ConfigRequest::TrustStatus {
                target: 0x99,
                network: 0xAAAA,
            },
            2_000,
        ));
        let query2 = host_ops::decode_config_trust_status(&body2).unwrap();
        foreign.network = 0xAAAA;
        foreign.nonce_echo = [0x5A; 16];
        assert_ne!(foreign.nonce_echo, query2.nonce);
        assert_eq!(
            done(lane.on_reply(
                &mut commit,
                req2,
                &trust_status_reply(0x99, &foreign),
                2_100
            )),
            ConfigOutcome::ProtocolError
        );
        // Standalone 0x27 read reports the RecoveryInfo verbatim.
        let (req3, body3) = emit(lane.submit(
            &mut commit,
            ConfigRequest::RecoveryInfo {
                target: 0x99,
                network: 0xAAAA,
                config_namespace: 1,
            },
            3_000,
        ));
        assert_eq!(body3[1], SUB_CONFIG_RECOVERY_INFO);
        let query3 = host_ops::decode_config_recovery_info(&body3).unwrap();
        assert_eq!(query3.config_namespace, 1);
        let info = RecoveryInfo {
            config_namespace: 1,
            schema: 1,
            nonce_echo: query3.nonce,
            network: 0xAAAA,
            store_floor: 3,
            decision_floor: 7,
            flags: 0x08,
            recovery_version: 2,
            profile_bits: 1,
            snapshot_hash: [0xAB; 32],
        };
        assert_eq!(
            done(lane.on_reply(&mut commit, req3, &recovery_info_reply(0x99, &info), 3_100)),
            ConfigOutcome::RecoveryInfo(info)
        );
        assert!(!lane.busy());
    }

    /// Fixed issuance inputs for the signed golden vectors: every byte
    /// the envelope binds is pinned here, so re-signing reproduces the
    /// checked-in objects bit-for-bit (dev HMAC and RFC-6979 COSE are
    /// both deterministic). The C++ suite verifies the same objects
    /// through the production Dev/COSE verifiers — the cross-language
    /// interop proof for the RCR2/RCC1 envelopes.
    struct GoldenCase {
        name: &'static str,
        profile: &'static str,
        kind: u8,
        mode: u8,
        op_id: [u8; 16],
        sequence: u64,
        reprovision: bool,
    }

    const GOLDEN_CASES: [GoldenCase; 6] = [
        GoldenCase {
            name: "dev_permit",
            profile: "dev-hmac-sha256-16",
            kind: ISSUE_KIND_PERMIT,
            mode: 0,
            op_id: [0x51; 16],
            sequence: 9,
            reprovision: false,
        },
        GoldenCase {
            name: "dev_recovery_adopt",
            profile: "dev-hmac-sha256-16",
            kind: ISSUE_KIND_RECOVERY,
            mode: 0,
            op_id: [0x52; 16],
            sequence: 10,
            reprovision: false,
        },
        GoldenCase {
            name: "dev_recovery_reprovision",
            profile: "dev-hmac-sha256-16",
            kind: ISSUE_KIND_RECOVERY,
            mode: 1,
            op_id: [0x53; 16],
            sequence: 11,
            reprovision: true,
        },
        GoldenCase {
            name: "cose_permit",
            profile: "rlcp1-cose-esp256",
            kind: ISSUE_KIND_PERMIT,
            mode: 0,
            op_id: [0x54; 16],
            sequence: 9,
            reprovision: false,
        },
        GoldenCase {
            name: "cose_recovery_adopt",
            profile: "rlcp1-cose-esp256",
            kind: ISSUE_KIND_RECOVERY,
            mode: 0,
            op_id: [0x55; 16],
            sequence: 10,
            reprovision: false,
        },
        GoldenCase {
            name: "cose_recovery_reprovision",
            profile: "rlcp1-cose-esp256",
            kind: ISSUE_KIND_RECOVERY,
            mode: 1,
            op_id: [0x56; 16],
            sequence: 11,
            reprovision: true,
        },
    ];

    const GOLDEN_DEV_KEY: [u8; 32] = [0x45; 32];

    fn golden_baseline() -> Vec<u8> {
        // {f1:u8=2} through the same encoder the lane uses — inside the
        // SDK schema (f1 allows 0..=2) so a real journal can deliver
        // the vector instead of refusing it at restore time.
        config_tlv_encode(&[field(1, ConfigFieldType::U8, &[2])]).unwrap()
    }

    fn golden_issuer(profile: u8) -> ConfigIssuer {
        let mut issuer = ConfigIssuer::new(GOLDEN_DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        if profile == ISSUE_PROFILE_COSE {
            issuer.set_profile(ISSUE_PROFILE_COSE);
            issuer.set_cose_signer(cose_signer());
        }
        issuer
    }

    fn golden_issue(case: &GoldenCase) -> (Vec<u8>, Vec<u8>) {
        // Match the full profile name: "rlcp1-cose-esp256" does not
        // start with "cose", and a prefix test here silently signs the
        // COSE vectors with the dev key under a COSE label.
        let profile = if case.profile == "rlcp1-cose-esp256" {
            ISSUE_PROFILE_COSE
        } else {
            ISSUE_PROFILE_DEV
        };
        let mut issuer = golden_issuer(profile);
        if case.kind == ISSUE_KIND_PERMIT {
            let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
            let ch = challenge(1, 1, &base, 4);
            issuer.note_challenge(&ch, 0x99, 1_000).unwrap();
            let draft = match issuer
                .prepare_propose(
                    0x99,
                    1,
                    1,
                    &base,
                    &[field(1, ConfigFieldType::U8, &[2])],
                    0,
                    1_100,
                    1,
                    case.sequence,
                    case.op_id,
                )
                .unwrap()
            {
                ProposeOutcome::Draft(draft) => draft,
                ProposeOutcome::NoChange => panic!("golden must draft"),
            };
            let issued = issuer.sign_permit(&draft, case.sequence).unwrap();
            assert_eq!(issued.operation_id, case.op_id);
            (issued.canonical, issued.object)
        } else {
            let baseline = if case.reprovision {
                golden_baseline()
            } else {
                Vec::new()
            };
            // Adopt binds the external survivor by its (pinned) hash; a
            // reprovision binds the carried baseline's own domain hash —
            // a placeholder here signs an object no device may deliver.
            let hash = if case.reprovision {
                snapshot_hash(1, 1, &baseline).unwrap()
            } else {
                [0xAB; 32]
            };
            let (intent, canonical) = issuer
                .prepare_recovery(
                    0x99,
                    1,
                    1,
                    case.mode,
                    4,
                    8,
                    hash,
                    &baseline,
                    1,
                    case.sequence,
                    case.op_id,
                )
                .unwrap();
            let issued = issuer
                .sign_recovery(&intent, &canonical, case.sequence)
                .unwrap();
            assert_eq!(issued.operation_id, case.op_id);
            (issued.canonical, issued.object)
        }
    }

    fn golden_json(case: &GoldenCase, canonical: &[u8], object: &[u8]) -> String {
        let profile = if case.profile.starts_with("cose") {
            ISSUE_PROFILE_COSE
        } else {
            ISSUE_PROFILE_DEV
        };
        let key_field = if profile == ISSUE_PROFILE_COSE {
            format!(
                "\"authority_pubkey_hex\":\"{}\"",
                hex_lower(&cose_signer().pubkey())
            )
        } else {
            format!("\"dev_key_hex\":\"{}\"", hex_lower(&GOLDEN_DEV_KEY))
        };
        format!(
            "{{\n  \"authority\":66,\n  \"authority_generation\":1,\n  \"authority_sequence\":{},\
             \n  \"canonical_hex\":\"{}\",\n  \"codec\":\"config_signed_object\",\n  \
             \"config_namespace\":1,\n  \"expect\":\"ok\",\n  \"format\":\"routeloom-config-signed-v1-golden\",\
             \n  \"kind\":{},\n  \"mode\":{},\n  \"name\":\"{}\",\n  \"network\":43690,\
             \n  \"object_hex\":\"{}\",\n  \"operation_id_hex\":\"{}\",\n  \"profile\":\"{}\",\
             \n  \"schema\":1,\n  \"target\":153,\n  {}\n}}\n",
            case.sequence,
            hex_lower(canonical),
            case.kind,
            case.mode,
            case.name,
            hex_lower(object),
            hex_lower(&case.op_id),
            case.profile,
            key_field
        )
    }

    #[test]
    fn signed_golden_vectors_match() {
        // The checked-in objects under protocol/config-signed-golden are
        // the cross-language contract: this test re-issues every vector
        // from fixed inputs and requires byte-identical output, while
        // the C++ suite verifies the same bytes through the production
        // Dev/COSE verifiers. Refresh with ROUTELOOM_WRITE_GOLDEN=1 and
        // review the diff — a changed byte is a wire break.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/config-signed-golden");
        let write = std::env::var("ROUTELOOM_WRITE_GOLDEN").as_deref() == Ok("1");
        if write {
            std::fs::create_dir_all(&dir).unwrap();
        }
        for case in &GOLDEN_CASES {
            let (canonical, object) = golden_issue(case);
            let rendered = golden_json(case, &canonical, &object);
            let path = dir.join(format!("{}.json", case.name));
            if write {
                std::fs::write(&path, &rendered).unwrap();
                continue;
            }
            let checked_in = std::fs::read_to_string(&path).expect("golden vector checked in");
            assert_eq!(
                rendered, checked_in,
                "golden {} drifted — re-sign mismatch",
                case.name
            );
        }
    }

    /// Structural + cryptographic assertions for one COSE envelope: the
    /// restricted profile parses, the kid names the authority, the
    /// payload is the canonical, the signature is low-S in range, and it
    /// verifies over the kind's own expected AAD.
    fn assert_cose_envelope(object: &[u8], canonical: &[u8], authority: u64, kind: u8) {
        use routeloom_provision::manifest::{cose_sig_structure, manifest_parse};
        use routeloom_provision::sha256::sha256 as p256_sha;
        let parts = manifest_parse(object).expect("restricted profile parses");
        assert_eq!(parts.root_id, authority);
        assert_eq!(parts.payload, canonical);
        assert_eq!(parts.signature.len(), 64);
        let mut sig = [0_u8; 64];
        sig.copy_from_slice(parts.signature);
        signature_range_check(&sig).expect("low-S in range");
        let (aad, from) = if kind == ISSUE_KIND_RECOVERY {
            let intent = routeloom_wire::endpoint::config_recovery_decode(canonical).unwrap();
            (
                config_recovery_aad(intent.network, intent.target, intent.config_namespace)
                    .unwrap()
                    .to_vec(),
                intent.authority,
            )
        } else {
            let command = routeloom_wire::endpoint::config_command_decode(canonical).unwrap();
            (
                config_permit_aad(command.network, command.target, command.config_namespace)
                    .unwrap()
                    .to_vec(),
                command.authority,
            )
        };
        assert_eq!(from, authority);
        let to_verify = cose_sig_structure(parts.protected_bytes, &aad, parts.payload).unwrap();
        let digest = p256_sha(&to_verify);
        assert!(ecdsa_p256_verify(&cose_signer().pubkey(), &digest, &sig));
        // A signature over the WRONG kind's AAD never verifies — the
        // envelope is bound to its own expected context.
        let mut wrong_aad = aad.clone();
        wrong_aad[0] ^= 0xFF;
        let wrong = cose_sig_structure(parts.protected_bytes, &wrong_aad, parts.payload).unwrap();
        assert!(!ecdsa_p256_verify(
            &cose_signer().pubkey(),
            &p256_sha(&wrong),
            &sig
        ));
    }
}
