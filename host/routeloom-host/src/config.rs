//! Remote-config issuer core (scope-gateway-config P5, 04-remote-config.md
//! §4.3, 05-wire-api.md §5.4–§5.6). Byte-for-byte mirror of the device-side
//! `ConfigIssuer::propose` and the `config_dev.cpp` development permit
//! profile — the host derives the same dev key, builds the same RCC1
//! canonical command and produces the same aad || canonical || tag16 permit.
//!
//! EXPERIMENTAL: the dev permit profile is an HMAC-SHA-256 over a shared
//! development key under SecurityProfile::Development. It is never a
//! production identity and the issuer reports itself as such.
//!
//! What lives here is the pure issuer core: the challenge-freshness ledger,
//! the CAS/revision binding, the NO_CHANGE shortcut and the signed-permit
//! construction. The durable outbox, the SingleAuthority global ledger and
//! the USB transport lane plug in around it — this module never performs I/O
//! and never claims a transport outcome as a config verdict.

use std::collections::HashMap;

use routeloom_protocol::host_ops::{
    self, ConfigOpsResult, SUB_CONFIG_CHALLENGE, SUB_CONFIG_PERMIT, SUB_CONFIG_STATUS,
};
use routeloom_wire::endpoint::{
    config_command_encode, config_namespace_valid, config_patch_apply, config_snapshot_hash_input,
    config_tlv_decode, control_challenge_decode, control_status_decode, ConfigCommand, ConfigField,
    ControlChallenge, ControlStatus,
};

use crate::canonical::sha256;

// The dev permit envelope (mirror of config_dev.hpp):
//   permit = aad || canonical || tag
//   aad    = "RouteLoom/config-permit/v1\0" || network u64 || target u64 || ns u16
//   tag    = HMAC-SHA256(dev_key, "RouteLoom/config-permit-dev/v1\0" || aad ||
//            canonical)[..16]
pub const CONFIG_PERMIT_DOMAIN: &[u8] = b"RouteLoom/config-permit/v1\0";
pub const CONFIG_DEV_PERMIT_DOMAIN: &[u8] = b"RouteLoom/config-permit-dev/v1\0";
pub const CONFIG_PERMIT_AAD_SIZE: usize = CONFIG_PERMIT_DOMAIN.len() + 8 + 8 + 2; // 44
pub const CONFIG_DEV_PERMIT_TAG_SIZE: usize = 16;
pub const CONFIG_PERMIT_OBJECT_MAX: usize = 1024;
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

/// aad = domain || network u64 || target u64 || config_namespace u16 (44 B).
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
/// permit = aad || canonical || tag16. Mirrors `DevConfigPermitSigner::sign`.
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

/// What `propose` produces. `NoChange` consumes neither a revision nor a
/// flash write — it is reported, never silently turned into a permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposeOutcome {
    Issued(IssuedPermit),
    NoChange,
}

/// The issuer's output for one accepted proposal: the canonical RCC1 command
/// (persisted to the outbox BEFORE signing), the signed permit object to
/// retransmit verbatim, and the derived operation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedPermit {
    pub canonical: Vec<u8>,
    pub permit: Vec<u8>,
    pub operation_id: [u8; 16],
    pub next_snapshot_hash: [u8; 32],
    pub next_revision: u64,
}

/// The Authority-side issuer (04 §4.3). Tracks challenge freshness per
/// (target, namespace); `propose` performs the CAS/revision binding and the
/// dev-profile sign exactly as `ConfigIssuer::propose` does on-device. The
/// SingleAuthority (generation, sequence) and outbox persistence are supplied
/// by the caller per proposal so this core stays pure and testable — the
/// durable commit order lives in the store/dispatch layer.
pub struct ConfigIssuer {
    dev_key: Vec<u8>,
    network: u64,
    authority: u64,
    safety_margin_ms: u32,
    challenges: HashMap<(u64, u16), ChallengeRecord>,
}

impl ConfigIssuer {
    /// `dev_key` is the domain-separated development permit key (never the
    /// raw link master key); an empty key makes every sign fail honestly.
    pub fn new(dev_key: Vec<u8>, network: u64, authority: u64, safety_margin_ms: u32) -> Self {
        Self {
            dev_key,
            network,
            authority,
            safety_margin_ms,
            challenges: HashMap::new(),
        }
    }

    pub fn ready(&self) -> bool {
        !self.dev_key.is_empty()
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
    /// ledger/entropy inputs the store layer supplies — the issuer binds them
    /// into the command but never invents them.
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
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
        let permit = dev_sign_permit(&self.dev_key, &command, &canonical)?;
        Ok(ProposeOutcome::Issued(IssuedPermit {
            canonical,
            permit,
            operation_id,
            next_snapshot_hash: next_hash,
            next_revision: command.next_revision,
        }))
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

/// A client request the lane drives. `Propose` runs challenge -> sign ->
/// permit -> status; the others are single queries.
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
    /// Challenge then sign `patch` against `base_snapshot` then transfer the
    /// permit then read the operation's terminal status. `apply_budget_ms==0`
    /// requests the whole remaining challenge budget.
    Propose {
        target: u64,
        config_namespace: u16,
        schema: u16,
        base_snapshot: Vec<u8>,
        patch: Vec<ConfigField>,
        apply_budget_ms: u32,
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
    /// Waiting on a 0x21 reply (permit transfer ack) before the status read.
    Permit,
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

/// Per-request state for a Propose in progress.
/// Entropy draw for operation_id / client_nonce, injected so tests are
/// deterministic — a `&mut [u8]` fill, same contract as `EntropySource`.
type EntropyFn = Box<dyn FnMut(&mut [u8])>;

struct ProposeState {
    target: u64,
    config_namespace: u16,
    schema: u16,
    base_snapshot: Vec<u8>,
    patch: Vec<ConfigField>,
    apply_budget_ms: u32,
    operation_id: [u8; 16],
    authority_generation: u32,
    authority_sequence: u64,
}

/// The lane state machine. `next_request` mirrors the dispatcher's request-id
/// allocation; entropy for operation_id / client_nonce is injected so tests
/// are deterministic.
pub struct ConfigLane {
    issuer: ConfigIssuer,
    next_request: u64,
    in_flight: Option<InFlight>,
    propose: Option<ProposeState>,
    /// Authority identity inputs the ledger layer supplies per propose.
    authority_generation: u32,
    authority_sequence: u64,
    /// Entropy draws (operation_id, client_nonce); injected for tests.
    entropy: EntropyFn,
    nonce_counter: u64,
}

impl ConfigLane {
    pub fn new(
        issuer: ConfigIssuer,
        authority_generation: u32,
        authority_sequence: u64,
        entropy: EntropyFn,
    ) -> Self {
        Self {
            issuer,
            next_request: 0,
            in_flight: None,
            propose: None,
            authority_generation,
            authority_sequence,
            entropy,
            nonce_counter: 0,
        }
    }

    pub fn set_authority(&mut self, generation: u32, sequence: u64) {
        self.authority_generation = generation;
        self.authority_sequence = sequence;
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
    /// flight — the caller must not submit a second.
    pub fn submit(&mut self, request: ConfigRequest, now_ms: u64) -> ConfigStep {
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
                    authority_sequence: self.authority_sequence,
                });
                self.emit_challenge(target, config_namespace, schema, now_ms)
            }
        }
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

    fn emit_permit(
        &mut self,
        target: u64,
        config_namespace: u16,
        permit: Vec<u8>,
        now_ms: u64,
    ) -> ConfigStep {
        let request = self.alloc_request();
        let body =
            match host_ops::encode_config_permit(&host_ops::ConfigPermitRequest { target, permit })
            {
                Ok(body) => body,
                Err(_) => {
                    self.propose = None;
                    return ConfigStep::Done(ConfigOutcome::ProtocolError);
                }
            };
        self.in_flight = Some(InFlight {
            request,
            phase: Phase::Permit,
            deadline_ms: now_ms + CONFIG_PERMIT_TIMEOUT_MS,
            target,
            config_namespace,
        });
        ConfigStep::Emit { request, body }
    }

    /// Consume an inbound reply body for `request`. `inner` is the verified
    /// host_ops inner body (schema|sub|len|payload). Returns Done when the
    /// request resolved, or the next Emit step for a multi-step propose.
    pub fn on_reply(&mut self, request: u64, inner: &[u8], now_ms: u64) -> ConfigStep {
        let Some(in_flight) = self.in_flight.take() else {
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        };
        if in_flight.request != request {
            // A reply naming a different lane id means the exchange is
            // torn upstream: the outstanding request can never resolve
            // cleanly now, so the lane clears rather than staying armed
            // behind an op that is already resolving ProtocolError.
            self.propose = None;
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        match in_flight.phase {
            Phase::Challenge {
                schema,
                client_nonce,
            } => self.on_challenge_reply(
                inner,
                in_flight.target,
                in_flight.config_namespace,
                schema,
                client_nonce,
                now_ms,
            ),
            Phase::Permit => self.on_permit_reply(inner, in_flight.target, now_ms),
            Phase::Status { operation_id } => self.on_status_reply(
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
            self.propose = None;
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let operation_id = self.propose.take().map(|p| p.operation_id);
        ConfigStep::Done(match in_flight.phase {
            Phase::Permit => ConfigOutcome::Indeterminate(operation_id),
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
        let operation_id = self.propose.take().map(|p| p.operation_id);
        Some(match phase {
            Phase::Permit => ConfigOutcome::Indeterminate(operation_id),
            _ => ConfigOutcome::Timeout,
        })
    }

    fn on_challenge_reply(
        &mut self,
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
                self.propose = None;
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        // A reply must echo the query's target: a refusal naming a
        // different target is a mismatched reply, never a claimed outcome.
        if reply.target != target {
            self.propose = None;
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let result = match ConfigOpsResult::try_from_u16(reply.result) {
            Ok(result) => result,
            Err(_) => {
                self.propose = None;
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if result != ConfigOpsResult::Ok {
            let operation_id = self.propose.take().map(|p| p.operation_id);
            return ConfigStep::Done(map_refusal(result, operation_id));
        }
        let challenge = match control_challenge_decode(&reply.body) {
            Ok(challenge) => challenge,
            Err(_) => {
                self.propose = None;
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
            self.propose = None;
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        if self.propose.is_none() {
            // Standalone challenge query: report the body, done.
            return ConfigStep::Done(ConfigOutcome::Challenged(challenge));
        }
        // Propose path: record the challenge then sign the permit. The
        // ProposeState stays live through the permit step so the follow-up
        // StatusQuery can read the same operation_id.
        let (target, config_namespace, schema) = {
            let propose = self.propose.as_ref().expect("checked");
            (propose.target, propose.config_namespace, propose.schema)
        };
        if let Err(error) = self.issuer.note_challenge(&challenge, target, now_ms) {
            // A challenge the ledger refuses leaves NO cached record —
            // signing a later propose against a stale nonce/revision would
            // mint a permit the target must reject.
            self.propose = None;
            return ConfigStep::Done(map_issue_error(error));
        }
        let outcome = {
            let propose = self.propose.as_ref().expect("checked");
            self.issuer.propose(
                target,
                config_namespace,
                schema,
                &propose.base_snapshot,
                &propose.patch,
                propose.apply_budget_ms,
                now_ms,
                propose.authority_generation,
                propose.authority_sequence,
                propose.operation_id,
            )
        };
        match outcome {
            Ok(ProposeOutcome::NoChange) => {
                self.propose = None;
                ConfigStep::Done(ConfigOutcome::NoChange)
            }
            Ok(ProposeOutcome::Issued(issued)) => {
                self.emit_permit(target, config_namespace, issued.permit, now_ms)
            }
            Err(error) => {
                self.propose = None;
                ConfigStep::Done(map_issue_error(error))
            }
        }
    }

    fn on_permit_reply(&mut self, inner: &[u8], target: u64, now_ms: u64) -> ConfigStep {
        let reply = match host_ops::decode_config_reply(inner, SUB_CONFIG_PERMIT) {
            Ok(reply) => reply,
            Err(_) => {
                self.propose = None;
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if reply.target != target {
            self.propose = None;
            return ConfigStep::Done(ConfigOutcome::ProtocolError);
        }
        let result = match ConfigOpsResult::try_from_u16(reply.result) {
            Ok(result) => result,
            Err(_) => {
                self.propose = None;
                return ConfigStep::Done(ConfigOutcome::ProtocolError);
            }
        };
        if result != ConfigOpsResult::Ok {
            let operation_id = self.propose.take().map(|p| p.operation_id);
            return ConfigStep::Done(map_refusal(result, operation_id));
        }
        // The object assembled — NOT a config verdict. Read the operation's
        // real status with a follow-up StatusQuery on the same operation_id.
        // The ProposeState stays live until the status reply resolves it.
        let Some(propose) = self.propose.as_ref() else {
            return ConfigStep::Done(ConfigOutcome::PermitAssembled(None));
        };
        let (target, config_namespace, operation_id) = (
            propose.target,
            propose.config_namespace,
            propose.operation_id,
        );
        self.emit_status(target, config_namespace, operation_id, now_ms)
    }

    fn on_status_reply(
        &mut self,
        inner: &[u8],
        target: u64,
        config_namespace: u16,
        operation_id: [u8; 16],
        _now_ms: u64,
    ) -> ConfigStep {
        self.propose = None;
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
/// (Invalid), and a CAS mismatch names a stale base snapshot distinctly so
/// the caller can re-read and retry — none of them is a ProtocolError,
/// which the wire reserves for malformed/mismatched replies.
fn map_issue_error(error: ConfigError) -> ConfigOutcome {
    match error {
        ConfigError::Expired => ConfigOutcome::Timeout,
        ConfigError::Stale => ConfigOutcome::RefusedStale,
        ConfigError::InvalidArgument | ConfigError::Malformed | ConfigError::TooLarge => {
            ConfigOutcome::Refused(ConfigOpsResult::Invalid)
        }
        _ => ConfigOutcome::ProtocolError,
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
            .propose(0x99, 1, 1, &base, &patch, 0, 2_000, 1, 9, [0x5A; 16])
            .unwrap();
        let ProposeOutcome::Issued(issued) = outcome else {
            panic!("expected issued");
        };
        // Envelope is aad(45) || canonical || tag(16).
        assert_eq!(
            issued.permit.len(),
            CONFIG_PERMIT_AAD_SIZE + issued.canonical.len() + CONFIG_DEV_PERMIT_TAG_SIZE
        );
        assert_eq!(&issued.permit[..27], b"RouteLoom/config-permit/v1\0");
        // Verify authenticates and returns the same canonical bytes.
        let recovered =
            dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &issued.permit).unwrap();
        assert_eq!(recovered, issued.canonical);
        // Tamper anywhere and verification denies.
        for pos in [0, 26, 40, issued.permit.len() - 1, issued.permit.len() / 2] {
            let mut bad = issued.permit.clone();
            bad[pos] ^= 0x01;
            assert!(dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 1, &bad).is_err());
        }
        // Wrong dev key denies.
        assert!(dev_permit_verify(b"other", 0xAAAA, 0x99, 1, 0x42, 1, &issued.permit).is_err());
        // Wrong authority / generation deny.
        assert!(dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x43, 1, &issued.permit).is_err());
        assert!(dev_permit_verify(DEV_KEY, 0xAAAA, 0x99, 1, 0x42, 2, &issued.permit).is_err());
    }

    #[test]
    fn propose_binds_cas_and_revision() {
        let mut issuer = ConfigIssuer::new(DEV_KEY.to_vec(), 0xAAAA, 0x42, 100);
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let ch = challenge(1, 1, &base, 4);
        issuer.note_challenge(&ch, 0x99, 1_000).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let issued = match issuer
            .propose(0x99, 1, 1, &base, &patch, 0, 2_000, 1, 9, [0x5A; 16])
            .unwrap()
        {
            ProposeOutcome::Issued(p) => p,
            _ => panic!("expected issued"),
        };
        let command = routeloom_wire::endpoint::config_command_decode(&issued.canonical).unwrap();
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
            issuer.propose(0x99, 1, 1, &base, &noop, 0, 2_000, 1, 9, [0x5A; 16]),
            Ok(ProposeOutcome::NoChange)
        );
        // A base snapshot that does not match the challenge hash -> Stale.
        let wrong_base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[9])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        assert_eq!(
            issuer.propose(0x99, 1, 1, &wrong_base, &patch, 0, 2_000, 1, 9, [0x5A; 16]),
            Err(ConfigError::Stale)
        );
        // Missing challenge -> ChallengeMissing.
        assert_eq!(
            issuer.propose(0x77, 1, 1, &base, &patch, 0, 2_000, 1, 9, [0x5A; 16]),
            Err(ConfigError::ChallengeMissing)
        );
        // Clock regressed -> ClockUncertain.
        assert_eq!(
            issuer.propose(0x99, 1, 1, &base, &patch, 0, 500, 1, 9, [0x5A; 16]),
            Err(ConfigError::ClockUncertain)
        );
        // Budget exhausted (now far past valid_for) -> Expired.
        assert_eq!(
            issuer.propose(
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
        ConfigLane::new(issuer, 1, 9, lane_entropy())
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
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let (req1, body1) = emit(lane.submit(
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            1_000,
        ));
        // The first emit is a ConfigChallenge request (0x23).
        assert_eq!(body1[1], SUB_CONFIG_CHALLENGE);
        assert!(lane.busy());
        // The device answers with a ControlChallenge bound to the base hash
        // and echoing the query's client_nonce.
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        let (req2, body2) = emit(lane.on_reply(req1, &challenge_reply(0x99, &ch), 1_100));
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
        let (req3, body3) = emit(lane.on_reply(req2, &ack, 1_200));
        // Object assembled -> the lane follows with a StatusQuery (0x20).
        assert_eq!(body3[1], host_ops::SUB_CONFIG_QUERY);
        // The terminal verdict arrives as a ControlStatus body echoing the
        // operation_id the StatusQuery carried.
        let op = host_ops::decode_config_query(&body3).unwrap().operation_id;
        let outcome = done(lane.on_reply(req3, &status_reply(0x99, &control_status(op)), 1_300));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status(op)));
        assert!(!lane.busy());
    }

    #[test]
    fn lane_standalone_challenge_and_status() {
        let mut lane = make_lane();
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        // Standalone challenge.
        let (req, body) = emit(lane.submit(
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
        let outcome = done(lane.on_reply(req, &challenge_reply(0x99, &ch), 1_100));
        assert_eq!(outcome, ConfigOutcome::Challenged(ch));
        // Standalone status lookup by operation id.
        let (req, body) = emit(lane.submit(
            ConfigRequest::Status {
                target: 0x99,
                config_namespace: 1,
                operation_id: [0x7B; 16],
            },
            2_000,
        ));
        assert_eq!(body[1], host_ops::SUB_CONFIG_QUERY);
        let outcome =
            done(lane.on_reply(req, &status_reply(0x99, &control_status([0x7B; 16])), 2_100));
        assert_eq!(outcome, ConfigOutcome::Statused(control_status([0x7B; 16])));
    }

    #[test]
    fn lane_reports_timeout_and_indeterminate() {
        let mut lane = make_lane();
        // A challenge that is never answered -> Timeout at the query deadline.
        let (_req, _body) = emit(lane.submit(
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
        let (req1, body1) = emit(lane.submit(
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            2_000,
        ));
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        let (_req2, _b2) = emit(lane.on_reply(req1, &challenge_reply(0x99, &ch), 2_100));
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
        let (_req, _body) = emit(lane.submit(
            ConfigRequest::Challenge {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
            },
            1_000,
        ));
        // A second submit while busy is refused Busy, and the in-flight is kept.
        let refused = done(lane.submit(
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
        let outcome = done(lane.on_reply(1, &busy, 1_020));
        assert_eq!(outcome, ConfigOutcome::Refused(ConfigOpsResult::Busy));
        // A dropped outbound frame resolves the request, not a silent retry.
        let (req, _b) = emit(lane.submit(
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
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        // Patch identical to base -> NO_CHANGE before any permit is sent.
        let patch = vec![field(1, ConfigFieldType::U8, &[1])];
        let (req1, body1) = emit(lane.submit(
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            1_000,
        ));
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        let outcome = done(lane.on_reply(req1, &challenge_reply(0x99, &ch), 1_100));
        assert_eq!(outcome, ConfigOutcome::NoChange);
        assert!(!lane.busy());
    }

    #[test]
    fn challenge_reply_must_echo_the_emitted_query() {
        let mut lane = make_lane();
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let (req, body) = emit(lane.submit(
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
            done(lane.on_reply(req, &challenge_reply(0x99, &foreign), 1_100)),
            ConfigOutcome::ProtocolError
        );
        assert!(!lane.busy());
        // A mismatched namespace or schema is the same torn exchange.
        for (ns, schema) in [(2_u16, 1_u16), (1, 9)] {
            let mut lane = make_lane();
            let (req, body) = emit(lane.submit(
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
                done(lane.on_reply(req, &challenge_reply(0x99, &ch), 1_100)),
                ConfigOutcome::ProtocolError
            );
        }
        // A reply naming a different target is equally foreign.
        let mut lane = make_lane();
        let (req, body) = emit(lane.submit(
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
            done(lane.on_reply(req, &challenge_reply(0x77, &ch), 1_100)),
            ConfigOutcome::ProtocolError
        );
        // And the echo-bound happy path still resolves Challenged.
        let mut lane = make_lane();
        let (req, body) = emit(lane.submit(
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
            done(lane.on_reply(req, &challenge_reply(0x99, &ch), 1_100)),
            ConfigOutcome::Challenged(ch)
        );
    }

    #[test]
    fn status_reply_must_echo_the_queried_operation() {
        let mut lane = make_lane();
        let (req, _body) = emit(lane.submit(
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
            done(lane.on_reply(req, &status_reply(0x99, &control_status([0x7C; 16])), 1_100)),
            ConfigOutcome::ProtocolError
        );
        assert!(!lane.busy());
        // Same for a foreign namespace or target.
        let mut lane = make_lane();
        let (req, _body) = emit(lane.submit(
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
            done(lane.on_reply(req, &status_reply(0x99, &foreign_ns), 1_100)),
            ConfigOutcome::ProtocolError
        );
        let mut lane = make_lane();
        let (req, _body) = emit(lane.submit(
            ConfigRequest::Status {
                target: 0x99,
                config_namespace: 1,
                operation_id: [0x7B; 16],
            },
            1_000,
        ));
        assert_eq!(
            done(lane.on_reply(req, &status_reply(0x77, &control_status([0x7B; 16])), 1_100)),
            ConfigOutcome::ProtocolError
        );
    }

    #[test]
    fn mismatched_lane_reply_clears_the_in_flight_step() {
        let mut lane = make_lane();
        let (req, _body) = emit(lane.submit(
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
            lane.on_reply(999, &[1, SUB_CONFIG_CHALLENGE, 0, 0], 1_020),
            ConfigStep::Done(ConfigOutcome::ProtocolError)
        );
        assert!(!lane.busy());
        // Same rule for a drop notification naming a different lane id.
        let mut lane = make_lane();
        let (req, _body) = emit(lane.submit(
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
            issuer.propose(0x99, 1, 1, &base, &patch, 0, 2_100, 1, 9, [0x5A; 16]),
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
        let base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[1])]).unwrap();
        let wrong_base = config_tlv_encode(&[field(1, ConfigFieldType::U8, &[9])]).unwrap();
        let patch = vec![field(1, ConfigFieldType::U8, &[2])];
        let (req1, body1) = emit(lane.submit(
            ConfigRequest::Propose {
                target: 0x99,
                config_namespace: 1,
                schema: 1,
                base_snapshot: wrong_base.clone(),
                patch,
                apply_budget_ms: 0,
            },
            1_000,
        ));
        let mut ch = challenge(1, 1, &base, 4);
        ch.client_nonce = emitted_nonce(&body1);
        assert_eq!(
            done(lane.on_reply(req1, &challenge_reply(0x99, &ch), 1_100)),
            ConfigOutcome::RefusedStale
        );
        assert!(!lane.busy());
    }
}
