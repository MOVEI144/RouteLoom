//! Site Authority service (docs/design/sdk-v1/02 §8–§9, 04 §3, 07; plan
//! P3-3): the EDHOC Responder of the zero-touch join, the member ledger and
//! the KGuard decision surface, running inside routeloom-host (08 §6 Q1:
//! the SAK never goes to an ESP32).
//!
//! Flow of one join (02 §4/§8), all driven through [`SiteService`]:
//!
//! 1. message_1 arrives relayed ([`transport::RelayUp`], step 1). Bounded
//!    admission (≤ [`MAX_LIVE_TXNS`] exchanges, one new message_1 per joiner
//!    MAC per [`JOINER_RATE_MS`]); beyond it the relay is aborted `busy`
//!    (no EDHOC session exists yet, so no JoinResult is possible).
//! 2. message_2: SiteOffer + the SiteCert by value in EAD_2, signed with the
//!    SAK through the `RootSigner` custody seam.
//! 3. message_3: DevCert (EAD_3 by value, kid-referenced) verified under the
//!    Device CA, kid = SHA-256(COSE_Key) checked, JoinRequest checked
//!    against the DevCert, Signature_3 verified. Any failure answers an
//!    EDHOC error, counts `rejected_unverified{reason}` and records nothing
//!    in the discovered table.
//! 4. DECIDE: an existing approval for (node, kid) re-issues the same
//!    MemberCert (`member.reissued`, no KGuard); a removed device that still
//!    holds site state gets `Removed` + a SAK-signed RemovalNotice; anything
//!    else is recorded as discovered and asked of KGuard (`join.request`)
//!    unless the policy is closed. KGuard silent past `decision_timeout_ms`
//!    → PendingAssignment (08 §6 Q7); a later decision applies at the next
//!    attempt.
//! 5. `join.decide allow` commits the ledger entry, the device row and the
//!    MemberCert in one store transaction *before* anything is sent; a store
//!    failure is AuthorityBusy / an API error, never success.
//! 6. message_4 carries the JoinResult; DAMS (Exporter 32771, provisional
//!    context) is stored with the delivery.
//!
//! Removal (04 §3): `revoke` commits the ledger entry, the new RRS1 (SAK
//! signed, full replacement, rs_epoch+1) and a staged next group key in one
//! transaction. Distribution (RevocationNotify, gossip, GK update — plans
//! P5/P6) is not implemented: operations report `distribution:
//! "not_implemented"` and count every member as unknown.
//!
//! Group key boundary (08 P5): the authority owns GK state as far as the
//! SitePackage needs it — the active (epoch, key), created at first start,
//! and one staged successor created on removal. Staging is not activation:
//! new joiners keep receiving the active key until P5 distributes and
//! activates the staged one (24 h / on-removal rotation, 08 §6 Q11).

// The relay input path (`handle_up` and everything behind it) is driven by
// the USB join relay, whose HostOps codec is defined concurrently (P3-2)
// and wired by the integrator; until then only the tests and the
// in-process transport exercise it, so a non-test build sees it unused.
#![cfg_attr(not(test), allow(dead_code))]

pub mod config;
pub mod records;
pub mod store;
pub mod transport;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use routeloom_edhoc::{
    crypto::random_scalar, error_message_unspecified, error_message_wrong_suite, EadItem,
    Error as EdhocError, LocalCredential, LocalKey, Method, PeerCredential, Responder, SUITE_2,
};
use routeloom_join::{
    dams_exporter_context, JoinEad, JoinIntent, JoinRequest, JoinResult, RemovalNotice, SiteOffer,
    SitePackage, DAMS_SIZE, EXPORTER_LABEL_DAMS, JOIN_EAD_CREDENTIAL_LABEL, PENDING_RETRY_MIN_S,
    RETRY_AFTER_MAX_S,
};
use routeloom_provision::credential::credential_kid;
use routeloom_provision::sdkv1::cert::{
    cert_decode, cert_issue, cert_verify, CertClaims, CertType, CERT_MAX,
};
use routeloom_provision::sdkv1::devca::devcert_verify;
use routeloom_provision::sdkv1::revocation::{
    revocation_issue, revocation_object_decode, RevocationEntry, RevocationReason, RevocationSet,
    REVOCATION_ENTRY_MAX,
};
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::{fill_random, RootSigner};

use crate::receive_log::hex_lower;
use records::{
    h16, op_token, request_token, role_name, DeviceFacts, Discovered, JoinRequestRec, Operation,
    StoredDecision, Verdict, Via, ROLE_ENDPOINT, ROLE_GATEWAY, ROLE_RELAY,
};
use store::{Batch, DeviceRow, DocKind, GroupKeyRow, LedgerRow, SiteStore};
use transport::{
    AbortReason, DownStatus, JoinTransport, Outbound, RelayDown, RelayKey, RelayUp,
    STEP_EDHOC_ERROR,
};

/// Concurrent join exchanges (02 §13 "authority同時参加 4件").
pub const MAX_LIVE_TXNS: usize = 4;
/// message_2 sent → message_3 must arrive within this (02 §8 M2_SENT).
pub const M3_TIMEOUT_MS: u64 = 10_000;
/// One new message_1 per joiner MAC per this (02 §13 flood bound).
pub const JOINER_RATE_MS: u64 = 2_000;
/// Discovered-device table (02 §9: 1024, LRU on last_seen).
pub const DISCOVERED_CAP: usize = 1024;
/// A discovered device raises `device.discovered` at most once a minute.
pub const DISCOVERED_EVENT_INTERVAL_MS: u64 = 60_000;
/// Open join requests (07 §3: 256, expired ones deleted).
pub const JOIN_REQUESTS_CAP: usize = 256;
/// An undelivered join request is forgotten after this.
pub const JOIN_REQUEST_TTL_MS: u64 = 24 * 3600 * 1000;
/// Members + removed devices the ledger keeps rows for (08 §6 Q8: ~100
/// boards per site; the bound leaves room for turnover).
pub const DEVICE_CAP: usize = 1024;
/// Idempotency records kept (oldest evicted).
pub const DECISIONS_CAP: usize = 1024;
/// Operations kept for `operations.get` (oldest evicted).
pub const OPERATIONS_CAP: usize = 256;
/// AuthorityBusy retry when the request table is full or the store failed.
pub const BUSY_RETRY_S: u32 = 30;
/// Slack under the pending retry: a device retrying this early is not
/// answered Busy (clock jitter between host and device).
const RETRY_SLACK_MS: u64 = 5_000;

// --- configuration -------------------------------------------------------------------

/// What the site PC is configured with (07 §3 `site`).
#[derive(Clone, Debug)]
pub struct SiteSetup {
    /// SiteCert (RLCW1, issued by the Site CA to the SAK).
    pub site_cert: Vec<u8>,
    /// When given, the SiteCert must verify under it (a misconfigured
    /// pairing is refused at start rather than at every join).
    pub site_ca_pubkey: Option<[u8; 64]>,
    pub device_ca_id: u64,
    pub device_ca_pubkey: [u8; 64],
    pub channel: u8,
    pub channel_epoch: u32,
    /// Gateway NodeIds announced in the SitePackage (1..=4).
    pub gateways: Vec<u64>,
}

struct Identity {
    site_id: u64,
    network: u64,
    site_cert: Vec<u8>,
    site_claims: CertClaims,
    sak_kid: [u8; 32],
    device_ca_id: u64,
    device_ca_pubkey: [u8; 64],
    channel: u8,
    channel_epoch: u32,
    gateways: [u64; 4],
    gateway_count: u8,
}

fn id_valid(id: u64) -> bool {
    id != 0 && id != u64::MAX
}

impl Identity {
    fn new(setup: &SiteSetup, sak: &dyn RootSigner) -> Result<Self, String> {
        let claims = match &setup.site_ca_pubkey {
            Some(ca) => {
                let (claims, ok) =
                    cert_verify(&setup.site_cert, ca).map_err(|e| format!("site cert: {e}"))?;
                if !ok {
                    return Err("site cert does not verify under the Site CA".into());
                }
                claims
            }
            None => cert_decode(&setup.site_cert).map_err(|e| format!("site cert: {e}"))?,
        };
        if claims.cert_type != CertType::Site {
            return Err("site cert is not a SiteCert".into());
        }
        if claims.pubkey != sak.pubkey() || claims.subject != sak.root_id() {
            return Err("the SAK does not match the SiteCert (cnf key / site_id)".into());
        }
        if !(1..=14).contains(&setup.channel) {
            return Err("channel must be 1..=14".into());
        }
        if setup.gateways.is_empty() || setup.gateways.len() > 4 {
            return Err("1..=4 gateways are required".into());
        }
        let mut gateways = [0_u64; 4];
        for (i, &gateway) in setup.gateways.iter().enumerate() {
            if !id_valid(gateway) || setup.gateways[..i].contains(&gateway) {
                return Err("gateway ids must be valid and distinct".into());
            }
            gateways[i] = gateway;
        }
        if !id_valid(setup.device_ca_id) {
            return Err("device ca id".into());
        }
        Ok(Self {
            site_id: claims.subject,
            network: (u64::from(claims.site_epoch) << 32) | u64::from(claims.network_low32),
            site_cert: setup.site_cert.clone(),
            sak_kid: credential_kid(&claims.pubkey),
            site_claims: claims,
            device_ca_id: setup.device_ca_id,
            device_ca_pubkey: setup.device_ca_pubkey,
            channel: setup.channel,
            channel_epoch: setup.channel_epoch,
            gateways,
            gateway_count: setup.gateways.len() as u8,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionMode {
    /// Ask KGuard (`join.request`), default.
    Kguard,
    /// Never ask: unapproved devices get PendingAssignment.
    Closed,
}

/// `join.policy.*` (07 §2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinPolicy {
    /// Members answer ZeroTouch DISCOVER (distributed to members by P3-2/P5;
    /// the authority treats `false` like `closed` for unapproved devices).
    pub zero_touch_open: bool,
    pub decision_mode: DecisionMode,
    pub decision_timeout_ms: u16,
    /// PendingAssignment retry when KGuard is silent or the policy closed.
    pub pending_retry_after_s: u32,
}

impl Default for JoinPolicy {
    fn default() -> Self {
        Self {
            zero_touch_open: true,
            decision_mode: DecisionMode::Kguard,
            decision_timeout_ms: 2000,
            pending_retry_after_s: 60,
        }
    }
}

impl JoinPolicy {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            u8::from(self.zero_touch_open),
            match self.decision_mode {
                DecisionMode::Kguard => 0,
                DecisionMode::Closed => 1,
            },
        ];
        out.extend_from_slice(&self.decision_timeout_ms.to_be_bytes());
        out.extend_from_slice(&self.pending_retry_after_s.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 8 || bytes[0] > 1 || bytes[1] > 1 {
            return None;
        }
        let policy = Self {
            zero_touch_open: bytes[0] == 1,
            decision_mode: if bytes[1] == 0 {
                DecisionMode::Kguard
            } else {
                DecisionMode::Closed
            },
            decision_timeout_ms: u16::from_be_bytes([bytes[2], bytes[3]]),
            pending_retry_after_s: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
        };
        policy.validate().ok()?;
        Some(policy)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if !(routeloom_join::DECISION_TIMEOUT_MIN_MS..=routeloom_join::DECISION_TIMEOUT_MAX_MS)
            .contains(&self.decision_timeout_ms)
        {
            return Err("decision_timeout_ms must be 500..=5000");
        }
        if !(PENDING_RETRY_MIN_S..=RETRY_AFTER_MAX_S).contains(&self.pending_retry_after_s) {
            return Err("pending_retry_after_s must be 30..=3600");
        }
        Ok(())
    }

    pub fn json(&self) -> String {
        format!(
            "{{\"zero_touch_open\":{},\"decision_mode\":\"{}\",\"decision_timeout_ms\":{},\"pending_retry_after_s\":{}}}",
            self.zero_touch_open,
            match self.decision_mode {
                DecisionMode::Kguard => "kguard",
                DecisionMode::Closed => "closed",
            },
            self.decision_timeout_ms,
            self.pending_retry_after_s
        )
    }

    fn asks_kguard(&self) -> bool {
        self.zero_touch_open && self.decision_mode == DecisionMode::Kguard
    }
}

// --- errors -------------------------------------------------------------------------------

/// An API-level refusal. `code` is the API1 error code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteError {
    pub code: &'static str,
    pub message: String,
    /// Extra `error.detail` members, `"k":v` joined by commas.
    pub extra: String,
    pub retryable: bool,
}

impl SiteError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            extra: String::new(),
            retryable: false,
        }
    }

    fn with(mut self, extra: String) -> Self {
        self.extra = extra;
        self
    }

    fn retry(mut self) -> Self {
        self.retryable = true;
        self
    }
}

fn store_failure(detail: &store::StoreError) -> SiteError {
    SiteError::new(
        "STORE_FAILURE",
        format!("the site store did not commit; nothing was changed ({detail})"),
    )
    .retry()
}

// --- the authority ----------------------------------------------------------------------------

/// The device a message_3 authenticated.
#[derive(Clone, Debug)]
struct Verified {
    facts: DeviceFacts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TxnState {
    AwaitMessage3,
    /// Waiting for KGuard on this join request.
    Deciding(u64),
}

struct Txn {
    key: RelayKey,
    via: Via,
    deadline_ms: u64,
    state: TxnState,
    responder: Responder,
    device: Option<Verified>,
}

#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub message_1: u64,
    pub message_1_refused: u64,
    pub busy_aborts: u64,
    pub unknown_relay: u64,
    pub timeouts: u64,
    pub rejected_unverified: BTreeMap<&'static str, u64>,
    pub allowed: u64,
    pub reissued: u64,
    pub pending: u64,
    pub denied: u64,
    pub removed_notices: u64,
    pub authority_busy: u64,
    pub store_failures: u64,
}

impl Counters {
    fn json(&self) -> String {
        let rejected = self
            .rejected_unverified
            .iter()
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"message_1\":{},\"message_1_refused\":{},\"busy_aborts\":{},\"unknown_relay\":{},\"timeouts\":{},\"rejected_unverified\":{{{rejected}}},\"allowed\":{},\"reissued\":{},\"pending\":{},\"denied\":{},\"removed_notices\":{},\"authority_busy\":{},\"store_failures\":{}}}",
            self.message_1,
            self.message_1_refused,
            self.busy_aborts,
            self.unknown_relay,
            self.timeouts,
            self.allowed,
            self.reissued,
            self.pending,
            self.denied,
            self.removed_notices,
            self.authority_busy,
            self.store_failures
        )
    }
}

/// `join.decide` input (after API validation).
#[derive(Clone, Debug)]
pub struct DecideRequest {
    pub join_request_id: u64,
    pub device: u64,
    pub verdict: Verdict,
    pub key: String,
}

/// `membership.revoke` input.
#[derive(Clone, Debug)]
pub struct RevokeRequest {
    pub device: u64,
    pub expected_generation: u32,
    pub reason: RevocationReason,
    pub key: String,
}

fn reason_name(reason: u8) -> &'static str {
    match reason {
        1 => "removed",
        2 => "lost",
        3 => "replaced",
        4 => "blocked",
        _ => "none",
    }
}

pub fn parse_reason(name: &str) -> Option<RevocationReason> {
    Some(match name {
        "removed" => RevocationReason::Removed,
        "lost" => RevocationReason::Lost,
        "replaced" => RevocationReason::Replaced,
        "blocked" => RevocationReason::Blocked,
        _ => return None,
    })
}

struct SakSigner<'a>(&'a dyn RootSigner);

impl routeloom_edhoc::Signer for SakSigner<'_> {
    fn sign(&self, sig_structure: &[u8]) -> routeloom_edhoc::Result<[u8; 64]> {
        self.0
            .sign(sig_structure)
            .map_err(|_| EdhocError::Crypto("SAK signer failed"))
    }
}

fn meta_u32(snapshot: &store::Snapshot, name: &str) -> Result<Option<u32>, String> {
    match snapshot.meta.get(name) {
        None => Ok(None),
        Some(bytes) => Ok(Some(u32::from_be_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("site store meta {name} corrupt"))?,
        ))),
    }
}

fn meta_u64(snapshot: &store::Snapshot, name: &str) -> Result<Option<u64>, String> {
    match snapshot.meta.get(name) {
        None => Ok(None),
        Some(bytes) => Ok(Some(u64::from_be_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("site store meta {name} corrupt"))?,
        ))),
    }
}

fn ledger_hash(prev: &[u8; 32], row: &LedgerRow) -> [u8; 32] {
    let mut input = Vec::with_capacity(160);
    input.extend_from_slice(b"RouteLoom/site-ledger/v1\0");
    input.extend_from_slice(prev);
    input.extend_from_slice(&row.seq.to_be_bytes());
    input.extend_from_slice(row.kind.as_bytes());
    input.push(0);
    input.extend_from_slice(&row.node.to_be_bytes());
    input.extend_from_slice(&row.kid);
    input.extend_from_slice(&row.generation.to_be_bytes());
    input.extend_from_slice(&row.digest);
    input.extend_from_slice(&row.ms.to_be_bytes());
    sha256(&input)
}

pub struct SiteAuthority {
    id: Identity,
    sak: Box<dyn RootSigner + Send>,
    store: Box<dyn SiteStore>,
    policy: JoinPolicy,
    devices: BTreeMap<u64, DeviceRow>,
    discovered: BTreeMap<u64, Discovered>,
    requests: BTreeMap<u64, JoinRequestRec>,
    decisions: BTreeMap<(u32, String), StoredDecision>,
    operations: BTreeMap<u64, Operation>,
    txns: Vec<Txn>,
    joiner_last_m1: HashMap<[u8; 6], u64>,
    rs_epoch: u32,
    rrs_entries: Vec<RevocationEntry>,
    gk_active: GroupKeyRow,
    gk_staged: Option<GroupKeyRow>,
    next_serial: u32,
    revision: u32,
    ledger_seq: u64,
    ledger_head: [u8; 32],
    next_request_id: u64,
    next_op_id: u64,
    pub counters: Counters,
    events: Vec<(u64, String)>,
    outbox: Vec<Outbound>,
}

impl SiteAuthority {
    /// Loads (or initialises) the authority from `store`. A store bound to
    /// another site, a corrupt row or a broken ledger chain refuses to start.
    pub fn open(
        setup: &SiteSetup,
        sak: Box<dyn RootSigner + Send>,
        mut store: Box<dyn SiteStore>,
        now_ms: u64,
    ) -> Result<Self, String> {
        let id = Identity::new(setup, sak.as_ref())?;
        let snapshot = store.load().map_err(|e| e.to_string())?;
        let mut binding = id.site_id.to_be_bytes().to_vec();
        binding.extend_from_slice(&id.network.to_be_bytes());
        binding.extend_from_slice(&id.sak_kid);
        let mut init = Batch::default();
        match snapshot.meta.get("site_binding") {
            Some(existing) if *existing != binding => return Err(
                "the site store belongs to another site / network / SAK (refusing to mix ledgers)"
                    .into(),
            ),
            Some(_) => {}
            None => init.meta.push(("site_binding", binding)),
        }
        let policy = match snapshot.meta.get("policy") {
            Some(bytes) => JoinPolicy::decode(bytes).ok_or("site store policy corrupt")?,
            None => JoinPolicy::default(),
        };
        let mut devices = BTreeMap::new();
        for row in &snapshot.devices {
            devices.insert(row.node, row.clone());
        }
        let mut ledger_head = [0_u8; 32];
        let mut ledger_seq = 0;
        for row in &snapshot.ledger {
            if row.seq != ledger_seq + 1 || ledger_hash(&ledger_head, row) != row.hash {
                return Err(format!("site ledger chain broken at seq {}", row.seq));
            }
            ledger_seq = row.seq;
            ledger_head = row.hash;
        }
        let mut discovered = BTreeMap::new();
        let mut requests = BTreeMap::new();
        let mut decisions = BTreeMap::new();
        let mut operations = BTreeMap::new();
        for ((kind, key), body) in &snapshot.docs {
            let bad = || format!("site store doc {key} corrupt");
            match kind {
                DocKind::Discovered => {
                    let d = Discovered::from_doc(body).ok_or_else(bad)?;
                    discovered.insert(d.facts.node, d);
                }
                DocKind::JoinRequest => {
                    let r = JoinRequestRec::from_doc(body).ok_or_else(bad)?;
                    requests.insert(r.id, r);
                }
                DocKind::Decision => {
                    let d = StoredDecision::from_doc(body).ok_or_else(bad)?;
                    decisions.insert((d.principal, d.key.clone()), d);
                }
                DocKind::Operation => {
                    let o = Operation::from_doc(body).ok_or_else(bad)?;
                    operations.insert(o.id, o);
                }
            }
        }
        let rs_epoch = meta_u32(&snapshot, "rs_epoch")?.unwrap_or(0);
        let rrs_entries = match snapshot.rrs.iter().max_by_key(|(e, _)| *e) {
            Some((epoch, object)) => {
                if *epoch != rs_epoch {
                    return Err("site store rs_epoch does not match the latest RRS1".into());
                }
                revocation_object_decode(object)
                    .map_err(|e| format!("stored RRS1 corrupt: {e}"))?
                    .entries
            }
            None if rs_epoch == 0 => Vec::new(),
            None => return Err("site store rs_epoch without an RRS1".into()),
        };
        let gk_active = snapshot
            .group_keys
            .iter()
            .filter(|g| g.state == "active")
            .max_by_key(|g| g.epoch)
            .cloned();
        let gk_staged = snapshot
            .group_keys
            .iter()
            .filter(|g| g.state == "staged")
            .max_by_key(|g| g.epoch)
            .cloned();
        let gk_active = match gk_active {
            Some(gk) => gk,
            None => {
                let mut key = [0_u8; 32];
                while key.iter().all(|&b| b == 0) {
                    fill_random(&mut key).map_err(|e| e.to_string())?;
                }
                let gk = GroupKeyRow {
                    epoch: 1,
                    key,
                    state: "active".into(),
                    created_ms: now_ms,
                };
                init.group_keys.push(gk.clone());
                gk
            }
        };
        let next_request_id = requests
            .keys()
            .max()
            .map_or(1, |m| m + 1)
            .max(meta_u64(&snapshot, "next_request_id")?.unwrap_or(1));
        let next_op_id = operations
            .keys()
            .max()
            .map_or(1, |m| m + 1)
            .max(meta_u64(&snapshot, "next_op_id")?.unwrap_or(1));
        if !init.is_empty() {
            store.commit(&init).map_err(|e| e.to_string())?;
        }
        Ok(Self {
            policy,
            devices,
            discovered,
            requests,
            decisions,
            operations,
            txns: Vec::new(),
            joiner_last_m1: HashMap::new(),
            rs_epoch,
            rrs_entries,
            gk_active,
            gk_staged,
            next_serial: meta_u32(&snapshot, "next_serial")?.unwrap_or(1),
            revision: meta_u32(&snapshot, "revision")?.unwrap_or(0),
            ledger_seq,
            ledger_head,
            next_request_id,
            next_op_id,
            counters: Counters::default(),
            events: Vec::new(),
            outbox: Vec::new(),
            id,
            sak,
            store,
        })
    }

    /// The ACL scope of the membership permissions: the site's wire network
    /// (network_low32, the id the rest of the host API uses).
    pub fn acl_network(&self) -> u64 {
        self.id.network & 0xFFFF_FFFF
    }

    pub fn site_id(&self) -> u64 {
        self.id.site_id
    }

    pub fn network(&self) -> u64 {
        self.id.network
    }

    pub fn policy(&self) -> JoinPolicy {
        self.policy
    }

    pub fn storage_durable(&self) -> bool {
        self.store.durable()
    }

    pub fn take_outbound(&mut self) -> Vec<Outbound> {
        std::mem::take(&mut self.outbox)
    }

    /// `(ms, fields)` for the daemon event ring (`"kind":...` first).
    pub fn take_events(&mut self) -> Vec<(u64, String)> {
        std::mem::take(&mut self.events)
    }

    fn event(&mut self, now_ms: u64, fields: String) {
        self.events.push((now_ms, fields));
    }

    fn down(&mut self, key: RelayKey, step: u8, status: DownStatus, body: Vec<u8>) {
        self.outbox.push(Outbound::Down(RelayDown {
            key,
            step,
            status,
            body,
        }));
    }

    fn abort(&mut self, key: RelayKey, reason: AbortReason) {
        self.outbox.push(Outbound::Abort { key, reason });
    }

    // --- relay input ---------------------------------------------------------------------

    pub fn handle_up(&mut self, up: RelayUp, now_ms: u64) {
        self.tick(now_ms);
        match up.step {
            1 => self.on_message_1(up, now_ms),
            3 => self.on_message_3(up, now_ms),
            _ => {
                // An Initiator error message or a stray step ends the relay.
                if let Some(i) = self.txns.iter().position(|t| t.key == up.key) {
                    self.txns.remove(i);
                } else {
                    self.counters.unknown_relay += 1;
                }
                self.abort(up.key, AbortReason::UnknownRelay);
            }
        }
    }

    fn on_message_1(&mut self, up: RelayUp, now_ms: u64) {
        self.counters.message_1 += 1;
        self.txns.retain(|t| t.key != up.key);
        self.joiner_last_m1
            .retain(|_, at| now_ms.saturating_sub(*at) < JOINER_RATE_MS);
        if self.txns.len() >= MAX_LIVE_TXNS || self.joiner_last_m1.contains_key(&up.key.joiner_mac)
        {
            self.counters.busy_aborts += 1;
            self.abort(up.key, AbortReason::Busy);
            return;
        }
        self.joiner_last_m1.insert(up.key.joiner_mac, now_ms);
        let mut c_r = [0_u8; 4];
        loop {
            if fill_random(&mut c_r).is_err() {
                self.abort(up.key, AbortReason::AuthorityError);
                return;
            }
            // Four bytes, never the one-byte int form, unique among live
            // exchanges (it names the authority channel, 02 §6).
            if c_r != [0; 4] && !self.txns.iter().any(|t| t.responder.c_r() == c_r) {
                break;
            }
        }
        let Ok(mut responder) = Responder::new(Method::SignatureSignature, c_r.to_vec()) else {
            self.abort(up.key, AbortReason::AuthorityError);
            return;
        };
        let message_1 = match responder.process_message_1(&up.body) {
            Ok(m) => m,
            Err(error) => {
                self.counters.message_1_refused += 1;
                let body = match error {
                    EdhocError::WrongSelectedSuite => error_message_wrong_suite(&[SUITE_2]),
                    _ => error_message_unspecified("message_1 refused"),
                };
                self.down(up.key, STEP_EDHOC_ERROR, DownStatus::Final, body);
                return;
            }
        };
        let intent_ok = split_join_ead(&message_1.ead, JoinEad::Intent, false)
            .ok()
            .and_then(|(value, _)| JoinIntent::decode(&value).ok())
            .is_some();
        if !intent_ok {
            self.counters.message_1_refused += 1;
            self.down(
                up.key,
                STEP_EDHOC_ERROR,
                DownStatus::Final,
                error_message_unspecified("message_1 refused"),
            );
            return;
        }
        let composed = (|| -> Result<Vec<u8>, String> {
            let offer =
                SiteOffer::from_site_cert(&self.id.site_claims, self.policy.decision_timeout_ms)
                    .and_then(|o| o.encode())
                    .map_err(|e| e.to_string())?;
            let ead_2 = [
                EadItem::critical(JoinEad::Offer as u32, offer.to_vec()),
                EadItem::critical(JOIN_EAD_CREDENTIAL_LABEL, self.id.site_cert.clone()),
            ];
            let signer = SakSigner(self.sak.as_ref());
            let local = LocalCredential {
                kid: &self.id.sak_kid,
                cred: &self.id.site_cert,
                key: LocalKey::Signature(&signer),
            };
            let y = random_scalar().map_err(|e| e.to_string())?;
            responder
                .compose_message_2(y, &local, &ead_2)
                .map_err(|e| e.to_string())
        })();
        match composed {
            Ok(message_2) => {
                self.txns.push(Txn {
                    key: up.key,
                    via: Via {
                        gateway: up.key.gateway,
                        proxy: up.key.proxy,
                        hops: up.hops,
                        rssi_dbm: up.joiner_rssi_dbm,
                    },
                    deadline_ms: now_ms + M3_TIMEOUT_MS,
                    state: TxnState::AwaitMessage3,
                    responder,
                    device: None,
                });
                self.down(up.key, 2, DownStatus::Continue, message_2);
            }
            Err(_) => self.abort(up.key, AbortReason::AuthorityError),
        }
    }

    fn on_message_3(&mut self, up: RelayUp, now_ms: u64) {
        let Some(index) = self
            .txns
            .iter()
            .position(|t| t.key == up.key && t.state == TxnState::AwaitMessage3)
        else {
            self.counters.unknown_relay += 1;
            self.abort(up.key, AbortReason::UnknownRelay);
            return;
        };
        let mut txn = self.txns.remove(index);
        let mut verified: Option<Verified> = None;
        let mut reason: &'static str = "message_3";
        let id = &self.id;
        let result = txn.responder.process_message_3(&up.body, |kid, ead| {
            let (request_bytes, cert) =
                split_join_ead(ead, JoinEad::Request, true).map_err(|r| {
                    reason = "ead";
                    r.to_string()
                })?;
            let cert = cert.unwrap_or_default();
            let claims =
                devcert_verify(&cert, id.device_ca_id, &id.device_ca_pubkey).map_err(|e| {
                    reason = "devcert";
                    e.to_string()
                })?;
            let kid: [u8; 32] = kid.try_into().map_err(|_| {
                reason = "kid";
                "kid length".to_string()
            })?;
            if credential_kid(&claims.pubkey) != kid {
                reason = "kid";
                return Err("kid does not name the DevCert key".into());
            }
            let request = JoinRequest::decode(&request_bytes)
                .and_then(|r| r.matches_dev_cert(&claims).map(|()| r))
                .map_err(|e| {
                    reason = "request";
                    e.to_string()
                })?;
            reason = "signature";
            verified = Some(Verified {
                facts: DeviceFacts {
                    node: claims.subject,
                    kid,
                    pubkey: claims.pubkey,
                    model: claims.model,
                    hw_rev: claims.hw_rev,
                    cert_serial: claims.serial,
                    fw_version: request.fw_version,
                    capability: request.capability,
                    requested_role: request.requested_role,
                    last_site_id: request.last_site_id,
                    last_generation: request.last_generation,
                    dev_cert: cert.clone(),
                },
            });
            Ok(PeerCredential {
                cred: cert,
                public_key: claims.pubkey,
            })
        });
        let device = match (result, verified) {
            (Ok(_), Some(device)) => device,
            _ => {
                *self.counters.rejected_unverified.entry(reason).or_insert(0) += 1;
                self.down(
                    up.key,
                    STEP_EDHOC_ERROR,
                    DownStatus::Final,
                    error_message_unspecified("join refused"),
                );
                return;
            }
        };
        txn.device = Some(device.clone());
        self.decide_for(txn, device, now_ms);
    }

    /// 02 §8 DECIDE for an authenticated device.
    fn decide_for(&mut self, mut txn: Txn, device: Verified, now_ms: u64) {
        let node = device.facts.node;
        let existing = self.devices.get(&node).cloned();
        let mut previously_removed = false;
        let mut kid_conflict = false;
        match existing {
            Some(row) if row.kid == device.facts.kid && row.member => {
                // Already approved: re-issue the same MemberCert, no KGuard.
                self.counters.reissued += 1;
                self.event(
                    now_ms,
                    format!(
                        "\"kind\":\"member.reissued\",\"device_id\":\"{}\",\"generation\":{},\"member_cert_serial\":{}",
                        h16(node),
                        row.generation,
                        row.member_cert_serial
                    ),
                );
                self.finish_allow(txn, &row, now_ms);
                return;
            }
            Some(row) if row.kid == device.facts.kid => {
                if device.facts.last_site_id == self.id.site_id {
                    // Still holds this site's state: tell it (04 §6.3).
                    self.finish_removed(txn, &row, now_ms);
                    return;
                }
                previously_removed = true;
            }
            // A removed row is history, not a conflict (07 §7): the
            // replacement key asks KGuard like any other device, marked
            // by the node's removal.
            Some(row) if !row.member => previously_removed = true,
            Some(_) => kid_conflict = true,
            None => {}
        }
        self.note_discovered(
            &device.facts,
            txn.via,
            previously_removed,
            kid_conflict,
            now_ms,
        );
        if !self.policy.asks_kguard() {
            let retry = self.policy.pending_retry_after_s;
            self.finish_verdict(
                txn,
                node,
                Verdict::Pending {
                    retry_after_s: retry,
                },
                now_ms,
            );
            return;
        }
        let open = self
            .requests
            .values()
            .find(|r| r.facts.node == node && r.facts.kid == device.facts.kid)
            .map(|r| (r.id, r.decision));
        if let Some((request_id, Some(verdict))) = open {
            // A decision taken after the previous attempt's deadline.
            self.close_request(request_id);
            self.finish_verdict(txn, node, verdict, now_ms);
            return;
        }
        let holdoff = self
            .discovered
            .get(&node)
            .and_then(|d| d.retry_not_before_ms)
            .filter(|&at| at > now_ms);
        if let Some(at) = holdoff {
            let seconds = (at - now_ms)
                .div_ceil(1000)
                .clamp(1, u64::from(RETRY_AFTER_MAX_S));
            self.finish_busy(txn, seconds as u32);
            return;
        }
        let deadline = now_ms + u64::from(self.policy.decision_timeout_ms);
        let request_id = match open {
            Some((request_id, None)) => {
                let request = self.requests.get_mut(&request_id).expect("open request");
                request.attempt += 1;
                request.updated_ms = now_ms;
                request.deadline_ms = deadline;
                request.via = txn.via;
                request.previously_removed = previously_removed;
                request.kid_conflict = kid_conflict;
                request_id
            }
            _ => {
                self.expire_requests(now_ms);
                if self.requests.len() >= JOIN_REQUESTS_CAP {
                    self.finish_busy(txn, BUSY_RETRY_S);
                    return;
                }
                let request_id = self.next_request_id;
                self.next_request_id += 1;
                self.requests.insert(
                    request_id,
                    JoinRequestRec {
                        id: request_id,
                        facts: device.facts.clone(),
                        previously_removed,
                        kid_conflict,
                        via: txn.via,
                        attempt: 1,
                        created_ms: now_ms,
                        updated_ms: now_ms,
                        deadline_ms: deadline,
                        decision: None,
                        decided_ms: None,
                        decision_result: None,
                    },
                );
                request_id
            }
        };
        let request = self.requests[&request_id].clone();
        let batch = Batch {
            meta: vec![(
                "next_request_id",
                self.next_request_id.to_be_bytes().to_vec(),
            )],
            docs: vec![(DocKind::JoinRequest, h16(request_id), Some(request.doc()))],
            ..Batch::default()
        };
        if let Err(error) = self.store.commit(&batch) {
            self.store_error(now_ms, &error);
        }
        if let Some(d) = self.discovered.get_mut(&node) {
            d.last_verdict = "awaiting".into();
        }
        self.event(now_ms, request.event_fields(now_ms));
        txn.state = TxnState::Deciding(request_id);
        txn.deadline_ms = deadline;
        self.txns.push(txn);
    }

    fn store_error(&mut self, now_ms: u64, error: &store::StoreError) {
        self.counters.store_failures += 1;
        self.event(
            now_ms,
            format!(
                "\"kind\":\"authority.error\",\"reason\":\"store\",\"detail\":\"{}\"",
                routeloom_json::escape_string(&error.0)
            ),
        );
    }

    fn close_request(&mut self, request_id: u64) {
        if self.requests.remove(&request_id).is_some() {
            let _ = self.store.commit(&Batch {
                docs: vec![(DocKind::JoinRequest, h16(request_id), None)],
                ..Batch::default()
            });
        }
    }

    fn expire_requests(&mut self, now_ms: u64) {
        let stale: Vec<u64> = self
            .requests
            .values()
            .filter(|r| now_ms.saturating_sub(r.updated_ms) > JOIN_REQUEST_TTL_MS)
            .map(|r| r.id)
            .collect();
        for id in stale {
            if !self.txns.iter().any(|t| t.state == TxnState::Deciding(id)) {
                self.close_request(id);
            }
        }
    }

    fn note_discovered(
        &mut self,
        facts: &DeviceFacts,
        via: Via,
        previously_removed: bool,
        kid_conflict: bool,
        now_ms: u64,
    ) {
        let node = facts.node;
        let first = !self.discovered.contains_key(&node);
        if first && self.discovered.len() >= DISCOVERED_CAP {
            // LRU on last_seen (02 §9).
            if let Some(oldest) = self
                .discovered
                .values()
                .min_by_key(|d| d.last_seen_ms)
                .map(|d| d.facts.node)
            {
                self.discovered.remove(&oldest);
                let _ = self.store.commit(&Batch {
                    docs: vec![(DocKind::Discovered, h16(oldest), None)],
                    ..Batch::default()
                });
            }
        }
        let entry = self.discovered.entry(node).or_insert_with(|| Discovered {
            facts: facts.clone(),
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            attempts: 0,
            via,
            last_verdict: "awaiting".into(),
            previously_removed,
            kid_conflict,
            retry_not_before_ms: None,
            last_event_ms: 0,
        });
        entry.facts = facts.clone();
        entry.last_seen_ms = now_ms;
        entry.attempts = entry.attempts.saturating_add(1);
        entry.via = via;
        entry.previously_removed = previously_removed;
        entry.kid_conflict = kid_conflict;
        let announce =
            first || now_ms.saturating_sub(entry.last_event_ms) >= DISCOVERED_EVENT_INTERVAL_MS;
        if announce {
            entry.last_event_ms = now_ms;
        }
        let doc = entry.doc();
        let fields = format!(
            "\"kind\":\"device.discovered\",\"device_id\":\"{}\",\"kid\":\"{}\",\"model\":{},\"first\":{first},\"previously_removed\":{previously_removed},\"kid_conflict\":{kid_conflict},\"via\":{}",
            h16(node),
            hex_lower(&facts.kid),
            facts.model,
            via.json()
        );
        let _ = self.store.commit(&Batch {
            docs: vec![(DocKind::Discovered, h16(node), Some(doc))],
            ..Batch::default()
        });
        if announce {
            self.event(now_ms, fields);
        }
    }

    fn set_discovered_verdict(&mut self, node: u64, label: &str, retry_not_before: Option<u64>) {
        if let Some(d) = self.discovered.get_mut(&node) {
            d.last_verdict = label.to_string();
            d.retry_not_before_ms = retry_not_before;
            let doc = d.doc();
            let _ = self.store.commit(&Batch {
                docs: vec![(DocKind::Discovered, h16(node), Some(doc))],
                ..Batch::default()
            });
        }
    }

    fn send_result(&mut self, mut txn: Txn, result: &JoinResult) -> bool {
        let composed = result
            .encode()
            .map_err(|e| e.to_string())
            .and_then(|value| {
                txn.responder
                    .compose_message_4(&[EadItem::critical(JoinEad::Result as u32, value)])
                    .map_err(|e| e.to_string())
            });
        match composed {
            Ok(message_4) => {
                self.down(txn.key, 4, DownStatus::Final, message_4);
                true
            }
            Err(_) => {
                self.abort(txn.key, AbortReason::AuthorityError);
                false
            }
        }
    }

    fn finish_busy(&mut self, txn: Txn, retry_after_s: u32) {
        self.counters.authority_busy += 1;
        if let Some(node) = txn.device.as_ref().map(|d| d.facts.node) {
            self.set_discovered_verdict(node, "busy", None);
        }
        self.send_result(txn, &JoinResult::AuthorityBusy { retry_after_s });
    }

    fn finish_verdict(&mut self, txn: Txn, node: u64, verdict: Verdict, now_ms: u64) {
        match verdict {
            Verdict::Allow { .. } => match self.devices.get(&node).cloned() {
                // The verdict was recorded for this key: if the row has
                // since moved to another key the device retries instead
                // of receiving a certificate it cannot use.
                Some(row)
                    if row.member
                        && txn.device.as_ref().is_some_and(|d| d.facts.kid == row.kid) =>
                {
                    self.finish_allow(txn, &row, now_ms)
                }
                _ => self.finish_busy(txn, BUSY_RETRY_S),
            },
            Verdict::Pending { retry_after_s } => {
                self.counters.pending += 1;
                let retry_at = now_ms + u64::from(retry_after_s) * 1000;
                self.set_discovered_verdict(
                    node,
                    "pending",
                    Some(retry_at.saturating_sub(RETRY_SLACK_MS)),
                );
                let mut ticket = [0_u8; 16];
                let _ = fill_random(&mut ticket);
                self.send_result(
                    txn,
                    &JoinResult::PendingAssignment {
                        retry_after_s,
                        ticket: ticket.to_vec(),
                    },
                );
            }
            Verdict::DenyNotHere | Verdict::DenyBlocked => {
                self.counters.denied += 1;
                self.set_discovered_verdict(node, verdict.label(), None);
                let result = if verdict == Verdict::DenyNotHere {
                    JoinResult::DenyNotHere
                } else {
                    JoinResult::DenyBlocked
                };
                self.send_result(txn, &result);
            }
        }
    }

    fn site_package(&self, role: u8, now_ms: u64) -> SitePackage {
        SitePackage {
            site_id: self.id.site_id,
            network: self.id.network,
            rs_epoch: self.rs_epoch,
            gk_epoch: self.gk_active.epoch,
            gk: self.gk_active.key,
            channel: self.id.channel,
            role,
            gateway_count: self.id.gateway_count,
            channel_epoch: self.id.channel_epoch,
            gateways: self.id.gateways,
            authority_time_s: now_ms / 1000,
            // The host clock is not authenticated; the device treats this
            // as a hint (02 §6.2) and no uncertainty bound is claimed.
            time_uncertainty_ms: u32::MAX,
            membership_revision: self.revision,
        }
    }

    /// Allow with the committed MemberCert. DAMS is exported and stored
    /// with the delivery *before* message_4 leaves; if that commit fails
    /// the device gets AuthorityBusy instead (never an unrecorded success).
    fn finish_allow(&mut self, txn: Txn, row: &DeviceRow, now_ms: u64) {
        let context = dams_exporter_context(
            self.id.network,
            row.node,
            self.id.site_id,
            &row.kid,
            &self.id.sak_kid,
        );
        let Ok(dams) = txn
            .responder
            .exporter(EXPORTER_LABEL_DAMS, &context, DAMS_SIZE)
        else {
            self.abort(txn.key, AbortReason::AuthorityError);
            return;
        };
        let mut updated = row.clone();
        updated.dams.copy_from_slice(&dams);
        updated.delivered_ms = Some(now_ms);
        updated.last_seen_ms = Some(now_ms);
        if let Err(error) = self.store.commit(&Batch {
            devices: vec![updated.clone()],
            ..Batch::default()
        }) {
            self.store_error(now_ms, &error);
            self.finish_busy(txn, BUSY_RETRY_S);
            return;
        }
        self.devices.insert(updated.node, updated.clone());
        self.set_discovered_verdict(row.node, "allowed", None);
        let result = JoinResult::Allow {
            member_cert: row.member_cert.clone(),
            site_package: self.site_package(row.role, now_ms),
            assignment_ticket: Vec::new(),
        };
        if self.send_result(txn, &result) {
            self.counters.allowed += 1;
        }
    }

    fn finish_removed(&mut self, txn: Txn, row: &DeviceRow, now_ms: u64) {
        let reason = match row.removal_reason {
            2 => RevocationReason::Lost,
            3 => RevocationReason::Replaced,
            4 => RevocationReason::Blocked,
            _ => RevocationReason::Removed,
        };
        let notice = RemovalNotice {
            reason,
            site_id: self.id.site_id,
            node_id: row.node,
            generation: row.generation,
            rs_epoch: self.rs_epoch.max(1),
        }
        .issue(self.id.network, self.sak.as_ref());
        match notice {
            Ok(removal_notice) => {
                self.counters.removed_notices += 1;
                self.event(
                    now_ms,
                    format!(
                        "\"kind\":\"member.removal_notified\",\"device_id\":\"{}\",\"generation\":{}",
                        h16(row.node),
                        row.generation
                    ),
                );
                self.send_result(txn, &JoinResult::Removed { removal_notice });
            }
            Err(_) => self.abort(txn.key, AbortReason::AuthorityError),
        }
    }

    /// Time-driven work: message_3 and decision deadlines.
    pub fn tick(&mut self, now_ms: u64) {
        let mut expired = Vec::new();
        let mut i = 0;
        while i < self.txns.len() {
            if self.txns[i].deadline_ms <= now_ms {
                expired.push(self.txns.remove(i));
            } else {
                i += 1;
            }
        }
        for txn in expired {
            match txn.state {
                TxnState::AwaitMessage3 => {
                    self.counters.timeouts += 1;
                    self.abort(txn.key, AbortReason::Timeout);
                }
                TxnState::Deciding(_) => {
                    // KGuard silent (08 §6 Q7): pending, the request stays
                    // open so a late decision applies at the next attempt.
                    let node = txn.device.as_ref().map_or(0, |d| d.facts.node);
                    let retry = self.policy.pending_retry_after_s;
                    self.finish_verdict(
                        txn,
                        node,
                        Verdict::Pending {
                            retry_after_s: retry,
                        },
                        now_ms,
                    );
                }
            }
        }
    }

    // --- KGuard decisions --------------------------------------------------------------------

    fn idempotent(
        &self,
        principal: u32,
        key: &str,
        digest: &[u8; 32],
    ) -> Option<Result<String, SiteError>> {
        let stored = self.decisions.get(&(principal, key.to_string()))?;
        Some(if stored.digest == *digest {
            Ok(stored.result.clone())
        } else {
            Err(SiteError::new(
                "CONFLICT",
                "same idempotency key with a different request",
            ))
        })
    }

    fn decision_doc(
        &mut self,
        batch: &mut Batch,
        principal: u32,
        key: &str,
        digest: [u8; 32],
        result: &str,
        now_ms: u64,
    ) {
        let stored = StoredDecision {
            principal,
            key: key.to_string(),
            digest,
            result: result.to_string(),
            ms: now_ms,
        };
        batch.docs.push((
            DocKind::Decision,
            StoredDecision::doc_key(principal, key),
            Some(stored.doc()),
        ));
        if self.decisions.len() >= DECISIONS_CAP {
            if let Some(oldest) = self
                .decisions
                .values()
                .min_by_key(|d| d.ms)
                .map(|d| (d.principal, d.key.clone()))
            {
                batch.docs.push((
                    DocKind::Decision,
                    StoredDecision::doc_key(oldest.0, &oldest.1),
                    None,
                ));
            }
        }
    }

    fn remember_decision(
        &mut self,
        principal: u32,
        key: &str,
        digest: [u8; 32],
        result: &str,
        now_ms: u64,
    ) {
        if self.decisions.len() >= DECISIONS_CAP {
            if let Some(oldest) = self
                .decisions
                .values()
                .min_by_key(|d| d.ms)
                .map(|d| (d.principal, d.key.clone()))
            {
                self.decisions.remove(&oldest);
            }
        }
        self.decisions.insert(
            (principal, key.to_string()),
            StoredDecision {
                principal,
                key: key.to_string(),
                digest,
                result: result.to_string(),
                ms: now_ms,
            },
        );
    }

    fn operation_doc(&mut self, batch: &mut Batch, op: &Operation) {
        batch
            .docs
            .push((DocKind::Operation, h16(op.id), Some(op.doc())));
        if self.operations.len() >= OPERATIONS_CAP {
            if let Some(&oldest) = self.operations.keys().next() {
                batch.docs.push((DocKind::Operation, h16(oldest), None));
            }
        }
        batch
            .meta
            .push(("next_op_id", (op.id + 1).to_be_bytes().to_vec()));
    }

    fn remember_operation(&mut self, op: Operation) {
        if self.operations.len() >= OPERATIONS_CAP {
            if let Some(&oldest) = self.operations.keys().next() {
                self.operations.remove(&oldest);
            }
        }
        self.next_op_id = op.id + 1;
        self.operations.insert(op.id, op);
    }

    fn ledger_row(
        &self,
        kind: &str,
        node: u64,
        kid: [u8; 32],
        generation: u32,
        digest: [u8; 32],
        now_ms: u64,
    ) -> LedgerRow {
        let mut row = LedgerRow {
            seq: self.ledger_seq + 1,
            kind: kind.to_string(),
            node,
            kid,
            generation,
            digest,
            ms: now_ms,
            hash: [0; 32],
        };
        row.hash = ledger_hash(&self.ledger_head, &row);
        row
    }

    /// True while the membership an allow `decision_result` committed is
    /// the live row: the node is a member with the request's kid at the
    /// committed generation.
    fn committed_allow_is_live(&self, open: &JoinRequestRec, result: &str) -> bool {
        let generation = routeloom_json::parse(result)
            .ok()
            .and_then(|json| json.get("generation").and_then(|v| v.as_u64()));
        self.devices.get(&open.facts.node).is_some_and(|row| {
            row.member && row.kid == open.facts.kid && Some(u64::from(row.generation)) == generation
        })
    }

    /// `join.decide` (07 §2.1). `allow` commits the approval before it
    /// answers `committed`; the verdict reaches a waiting exchange at once,
    /// otherwise the device's next attempt.
    pub fn decide(
        &mut self,
        principal: u32,
        request: DecideRequest,
        now_ms: u64,
    ) -> Result<String, SiteError> {
        let digest = sha256(
            format!(
                "join.decide|{}|{}|{{{}}}",
                request.join_request_id,
                request.device,
                request.verdict.json_fields()
            )
            .as_bytes(),
        );
        if let Some(answer) = self.idempotent(principal, &request.key, &digest) {
            return answer;
        }
        let Some(open) = self.requests.get(&request.join_request_id).cloned() else {
            return Err(SiteError::new(
                "NOT_FOUND",
                "no open join request with that id (delivered, expired or never issued)",
            ));
        };
        if open.facts.node != request.device {
            return Err(SiteError::new(
                "CONFLICT",
                "device_id does not match the join request",
            ));
        }
        if let Some(existing) = open.decision {
            if existing == request.verdict {
                if let Some(result) = &open.decision_result {
                    // A stored "committed" answer is only valid while the
                    // membership it created is still live; after a revoke
                    // or a replacement it would lie about current state.
                    if matches!(existing, Verdict::Allow { .. })
                        && !self.committed_allow_is_live(&open, result)
                    {
                        return Err(SiteError::new(
                            "CONFLICT",
                            "the membership this request committed is no longer live (removed or replaced)",
                        ));
                    }
                    return Ok(result.clone());
                }
            }
            return Err(SiteError::new(
                "CONFLICT",
                "this join request already has a different verdict",
            )
            .with(format!("\"existing\":{{{}}}", existing.json_fields())));
        }
        let waiting = self
            .txns
            .iter()
            .position(|t| t.state == TxnState::Deciding(open.id));
        let applied = if waiting.is_some() {
            "current_attempt"
        } else {
            "next_attempt"
        };
        let mut batch = Batch::default();
        let result;
        let mut approved: Option<(DeviceRow, LedgerRow, Operation)> = None;
        match request.verdict {
            Verdict::Allow { role } => {
                // The flag stored with the request is stale information:
                // the conflict is judged on the membership as it is now,
                // inside this commit. A removed row does not conflict.
                if self
                    .devices
                    .get(&open.facts.node)
                    .is_some_and(|row| row.member && row.kid != open.facts.kid)
                {
                    return Err(SiteError::new(
                        "CONFLICT",
                        "another key holds this device id here; revoke that membership first (07 §7)",
                    ));
                }
                let capability_ok = match role {
                    ROLE_RELAY => {
                        open.facts.capability & routeloom_join::JOIN_CAPABILITY_RELAY != 0
                    }
                    ROLE_GATEWAY => {
                        open.facts.capability & routeloom_join::JOIN_CAPABILITY_GATEWAY != 0
                    }
                    ROLE_ENDPOINT => true,
                    _ => false,
                };
                if !capability_ok {
                    return Err(SiteError::new(
                        "INVALID_ARGUMENT",
                        "the device does not report the capability this role needs",
                    ));
                }
                if !self.devices.contains_key(&open.facts.node) && self.devices.len() >= DEVICE_CAP
                {
                    return Err(SiteError::new("NO_CAPACITY", "the member ledger is full").retry());
                }
                let generation = self
                    .devices
                    .get(&open.facts.node)
                    .map_or(1, |d| d.generation.saturating_add(1));
                let serial = self.next_serial;
                let claims = CertClaims {
                    cert_type: CertType::Member,
                    issuer: self.id.site_id,
                    subject: open.facts.node,
                    pubkey: open.facts.pubkey,
                    network: self.id.network,
                    role: u32::from(role),
                    assignment_generation: generation,
                    site_epoch: self.id.site_claims.site_epoch,
                    serial,
                    ..CertClaims::default()
                };
                let member_cert = cert_issue(&claims, self.sak.as_ref()).map_err(|e| {
                    SiteError::new("AUTHORITY_ERROR", format!("MemberCert issue failed: {e}"))
                })?;
                debug_assert!(member_cert.len() <= CERT_MAX);
                let row = DeviceRow {
                    node: open.facts.node,
                    kid: open.facts.kid,
                    dev_cert: open.facts.dev_cert.clone(),
                    model: open.facts.model,
                    hw_rev: open.facts.hw_rev,
                    cert_serial: open.facts.cert_serial,
                    member: true,
                    generation,
                    role,
                    member_cert_serial: serial,
                    member_cert,
                    confirmed: false,
                    dams: [0; 32],
                    approved_ms: now_ms,
                    delivered_ms: None,
                    confirmed_ms: None,
                    last_seen_ms: None,
                    removed_ms: None,
                    removal_reason: 0,
                };
                let ledger = self.ledger_row(
                    "approve",
                    row.node,
                    row.kid,
                    generation,
                    sha256(&row.member_cert),
                    now_ms,
                );
                let op = Operation {
                    id: self.next_op_id,
                    kind: "approve".into(),
                    node: row.node,
                    generation,
                    member_cert_serial: serial,
                    rs_epoch: self.rs_epoch,
                    gk_from: self.gk_active.epoch,
                    gk_to: self.gk_active.epoch,
                    created_ms: now_ms,
                };
                result = format!(
                    "{{\"state\":\"committed\",\"join_request_id\":\"{}\",\"device_id\":\"{}\",\"verdict\":\"allow\",\"role\":\"{}\",\"generation\":{generation},\"member_cert_serial\":{serial},\"operation_id\":\"{}\",\"applied\":\"{applied}\"}}",
                    request_token(open.id),
                    h16(row.node),
                    role_name(role),
                    op_token(op.id)
                );
                batch.devices.push(row.clone());
                batch.ledger.push(ledger.clone());
                batch
                    .meta
                    .push(("next_serial", (serial + 1).to_be_bytes().to_vec()));
                batch
                    .meta
                    .push(("revision", (self.revision + 1).to_be_bytes().to_vec()));
                self.operation_doc(&mut batch, &op);
                approved = Some((row, ledger, op));
            }
            _ => {
                result = format!(
                    "{{\"state\":\"recorded\",\"join_request_id\":\"{}\",\"device_id\":\"{}\",{},\"applied\":\"{applied}\"}}",
                    request_token(open.id),
                    h16(open.facts.node),
                    request.verdict.json_fields()
                );
            }
        }
        let mut updated = open.clone();
        updated.decision = Some(request.verdict);
        updated.decided_ms = Some(now_ms);
        updated.decision_result = Some(result.clone());
        batch
            .docs
            .push((DocKind::JoinRequest, h16(open.id), Some(updated.doc())));
        self.decision_doc(&mut batch, principal, &request.key, digest, &result, now_ms);
        if let Err(error) = self.store.commit(&batch) {
            self.store_error(now_ms, &error);
            return Err(store_failure(&error));
        }
        // Committed: now the RAM model follows.
        if let Some((row, ledger, op)) = approved {
            self.ledger_seq = ledger.seq;
            self.ledger_head = ledger.hash;
            self.next_serial = row.member_cert_serial + 1;
            self.revision += 1;
            self.devices.insert(row.node, row);
            self.remember_operation(op);
        }
        self.remember_decision(principal, &request.key, digest, &result, now_ms);
        self.requests.insert(open.id, updated);
        self.event(
            now_ms,
            format!(
                "\"kind\":\"join.decided\",\"join_request_id\":\"{}\",\"device_id\":\"{}\",{},\"applied\":\"{applied}\",\"late\":{}",
                request_token(open.id),
                h16(open.facts.node),
                request.verdict.json_fields(),
                waiting.is_none()
            ),
        );
        if let Some(index) = waiting {
            let txn = self.txns.remove(index);
            self.close_request(open.id);
            self.finish_verdict(txn, open.facts.node, request.verdict, now_ms);
        }
        Ok(result)
    }

    /// `membership.revoke` (04 §3, 07 §2.2).
    pub fn revoke(
        &mut self,
        principal: u32,
        request: RevokeRequest,
        now_ms: u64,
    ) -> Result<String, SiteError> {
        let digest = sha256(
            format!(
                "membership.revoke|{}|{}|{}",
                request.device, request.expected_generation, request.reason as u8
            )
            .as_bytes(),
        );
        if let Some(answer) = self.idempotent(principal, &request.key, &digest) {
            return answer;
        }
        let Some(row) = self.devices.get(&request.device).cloned() else {
            return Err(SiteError::new("NOT_FOUND", "no member with that device id"));
        };
        if !row.member {
            return Err(SiteError::new("CONFLICT", "the device is already removed")
                .with(format!("\"generation\":{}", row.generation)));
        }
        if row.generation != request.expected_generation {
            return Err(SiteError::new(
                "CONFLICT",
                "expected_generation does not match the current assignment",
            )
            .with(format!("\"generation\":{}", row.generation)));
        }
        let mut entries: Vec<RevocationEntry> = self
            .rrs_entries
            .iter()
            .filter(|e| e.node_id != row.node)
            .cloned()
            .collect();
        entries.push(RevocationEntry {
            node_id: row.node,
            min_generation: row.generation + 1,
            reason: request.reason,
        });
        entries.sort_by_key(|e| e.node_id);
        if entries.len() > REVOCATION_ENTRY_MAX {
            return Err(SiteError::new(
                "CUTOVER_REQUIRED",
                "the revocation set is full (32 entries); a site_epoch cutover (04 §7, P6-2) must empty it first",
            ));
        }
        let rs_epoch = self.rs_epoch + 1;
        let set = RevocationSet {
            site_id: self.id.site_id,
            network: self.id.network,
            rs_epoch,
            site_epoch_floor: self.id.site_claims.site_epoch,
            entries: entries.clone(),
        };
        let object = revocation_issue(&set, self.sak.as_ref())
            .map_err(|e| SiteError::new("AUTHORITY_ERROR", format!("RRS1 issue failed: {e}")))?;
        let staged = match &self.gk_staged {
            Some(staged) => (staged.clone(), false),
            None => {
                let mut key = [0_u8; 32];
                while key.iter().all(|&b| b == 0) {
                    fill_random(&mut key).map_err(|e| {
                        SiteError::new("AUTHORITY_ERROR", format!("group key: {e}"))
                    })?;
                }
                (
                    GroupKeyRow {
                        epoch: self.gk_active.epoch + 1,
                        key,
                        state: "staged".into(),
                        created_ms: now_ms,
                    },
                    true,
                )
            }
        };
        let mut removed = row.clone();
        removed.member = false;
        removed.removed_ms = Some(now_ms);
        removed.removal_reason = request.reason as u8;
        removed.dams = [0; 32];
        let ledger = self.ledger_row(
            "revoke",
            row.node,
            row.kid,
            row.generation,
            sha256(&object),
            now_ms,
        );
        let op = Operation {
            id: self.next_op_id,
            kind: "revoke".into(),
            node: row.node,
            generation: row.generation,
            member_cert_serial: row.member_cert_serial,
            rs_epoch,
            gk_from: self.gk_active.epoch,
            gk_to: staged.0.epoch,
            created_ms: now_ms,
        };
        let result = format!(
            "{{\"operation_id\":\"{}\",\"state\":\"committed\",\"device_id\":\"{}\",\"generation\":{},\"rs_epoch\":{rs_epoch},\"gk_rotation\":{{\"from\":{},\"to\":{},\"state\":\"staged\"}},\"distribution\":\"not_implemented\"}}",
            op_token(op.id),
            h16(row.node),
            row.generation,
            self.gk_active.epoch,
            staged.0.epoch
        );
        let mut batch = Batch {
            devices: vec![removed.clone()],
            ledger: vec![ledger.clone()],
            rrs: vec![(rs_epoch, object)],
            meta: vec![
                ("rs_epoch", rs_epoch.to_be_bytes().to_vec()),
                ("revision", (self.revision + 1).to_be_bytes().to_vec()),
            ],
            ..Batch::default()
        };
        if staged.1 {
            batch.group_keys.push(staged.0.clone());
        }
        self.operation_doc(&mut batch, &op);
        self.decision_doc(&mut batch, principal, &request.key, digest, &result, now_ms);
        if let Err(error) = self.store.commit(&batch) {
            self.store_error(now_ms, &error);
            return Err(store_failure(&error));
        }
        self.ledger_seq = ledger.seq;
        self.ledger_head = ledger.hash;
        self.revision += 1;
        self.rs_epoch = rs_epoch;
        self.rrs_entries = entries.clone();
        self.devices.insert(removed.node, removed);
        if staged.1 {
            self.gk_staged = Some(staged.0.clone());
        }
        self.remember_operation(op.clone());
        self.remember_decision(principal, &request.key, digest, &result, now_ms);
        self.event(
            now_ms,
            format!(
                "\"kind\":\"member.revoked\",\"device_id\":\"{}\",\"generation\":{},\"reason\":\"{}\",\"rs_epoch\":{rs_epoch},\"operation_id\":\"{}\"",
                h16(row.node),
                row.generation,
                reason_name(request.reason as u8),
                op_token(op.id)
            ),
        );
        self.event(
            now_ms,
            format!(
                "\"kind\":\"rrs.published\",\"rs_epoch\":{rs_epoch},\"entries\":{},\"distribution\":\"not_implemented\"",
                entries.len()
            ),
        );
        if staged.1 {
            self.event(
                now_ms,
                format!(
                    "\"kind\":\"gk.staged\",\"from\":{},\"to\":{},\"cause\":\"removal\",\"distribution\":\"not_implemented\"",
                    self.gk_active.epoch, staged.0.epoch
                ),
            );
        }
        Ok(result)
    }

    /// JoinConfirm arrived on the authority channel (P5 wires the channel;
    /// this is the hook). Moves the member to `active`.
    pub fn member_confirmed(&mut self, node: u64, generation: u32, now_ms: u64) -> bool {
        let Some(row) = self.devices.get(&node).cloned() else {
            return false;
        };
        if !row.member || row.generation != generation || row.confirmed {
            return false;
        }
        let mut updated = row;
        updated.confirmed = true;
        updated.confirmed_ms = Some(now_ms);
        if self
            .store
            .commit(&Batch {
                devices: vec![updated.clone()],
                ..Batch::default()
            })
            .is_err()
        {
            return false;
        }
        self.devices.insert(node, updated);
        self.event(
            now_ms,
            format!(
                "\"kind\":\"member.confirmed\",\"device_id\":\"{}\",\"generation\":{generation}",
                h16(node)
            ),
        );
        true
    }

    pub fn set_policy(&mut self, policy: JoinPolicy) -> Result<String, SiteError> {
        policy
            .validate()
            .map_err(|m| SiteError::new("INVALID_ARGUMENT", m))?;
        self.store
            .commit(&Batch {
                meta: vec![("policy", policy.encode())],
                ..Batch::default()
            })
            .map_err(|e| store_failure(&e))?;
        self.policy = policy;
        Ok(policy.json())
    }

    // --- read side ------------------------------------------------------------------------------

    pub fn status_json(&self, now_ms: u64) -> String {
        let members = self.devices.values().filter(|d| d.member).count();
        let unconfirmed = self
            .devices
            .values()
            .filter(|d| d.member && !d.confirmed)
            .count();
        let removed = self.devices.values().filter(|d| !d.member).count();
        let gateways = self.id.gateways[..usize::from(self.id.gateway_count)]
            .iter()
            .map(|g| format!("\"{}\"", h16(*g)))
            .collect::<Vec<_>>()
            .join(",");
        let staged = self
            .gk_staged
            .as_ref()
            .map_or_else(|| "null".to_string(), |g| g.epoch.to_string());
        format!(
            "{{\"site_id\":\"{}\",\"network\":\"{}\",\"network_low32\":\"{:08x}\",\"site_epoch\":{},\"site_cert_serial\":{},\"sak_fingerprint\":\"{}\",\"device_ca_id\":\"{}\",\"rs_epoch\":{},\"gk_epoch\":{},\"gk_staged\":{staged},\"members\":{members},\"members_unconfirmed\":{unconfirmed},\"removed\":{removed},\"discovered\":{},\"join_requests\":{},\"live_exchanges\":{},\"channel\":{},\"channel_epoch\":{},\"gateways\":[{gateways}],\"membership_revision\":{},\"ledger_seq\":{},\"storage_durable\":{},\"policy\":{},\"counters\":{},\"clock\":\"host_unix_ms\",\"now_ms\":{now_ms}}}",
            h16(self.id.site_id),
            h16(self.id.network),
            self.id.network & 0xFFFF_FFFF,
            self.id.site_claims.site_epoch,
            self.id.site_claims.serial,
            hex_lower(&self.id.sak_kid),
            h16(self.id.device_ca_id),
            self.rs_epoch,
            self.gk_active.epoch,
            self.discovered.len(),
            self.requests.len(),
            self.txns.len(),
            self.id.channel,
            self.id.channel_epoch,
            self.revision,
            self.ledger_seq,
            self.store.durable(),
            self.policy.json(),
            self.counters.json()
        )
    }

    pub fn join_requests_json(&self, now_ms: u64) -> String {
        let items = self
            .requests
            .values()
            .map(|r| r.api_json(now_ms))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"requests\":[{items}],\"max\":{JOIN_REQUESTS_CAP},\"clock\":\"host_unix_ms\"}}")
    }

    fn page<'a, T: 'a>(
        items: impl Iterator<Item = (&'a u64, &'a T)>,
        after: Option<u64>,
        limit: usize,
        json: impl Fn(&T) -> String,
    ) -> (String, Option<u64>) {
        let mut out = Vec::new();
        let mut last = None;
        let mut more = false;
        for (&node, item) in items {
            if after.is_some_and(|a| node <= a) {
                continue;
            }
            if out.len() == limit {
                more = true;
                break;
            }
            out.push(json(item));
            last = Some(node);
        }
        (out.join(","), if more { last } else { None })
    }

    pub fn discovered_json(&self, after: Option<u64>, limit: usize) -> String {
        let (items, next) = Self::page(self.discovered.iter(), after, limit, Discovered::api_json);
        format!(
            "{{\"devices\":[{items}],\"next_after\":{},\"total\":{},\"max\":{DISCOVERED_CAP},\"clock\":\"host_unix_ms\"}}",
            next.map_or_else(|| "null".to_string(), |n| format!("\"{}\"", h16(n))),
            self.discovered.len()
        )
    }

    fn member_json(row: &DeviceRow) -> String {
        let opt = |v: Option<u64>| v.map_or_else(|| "null".to_string(), |v| v.to_string());
        format!(
            "{{\"device_id\":\"{}\",\"kid\":\"{}\",\"state\":\"{}\",\"generation\":{},\"role\":\"{}\",\"member_cert_serial\":{},\"confirm_state\":{},\"delivered\":{},\"model\":{},\"hw_rev\":{},\"cert_serial\":{},\"approved_ms\":{},\"delivered_ms\":{},\"confirmed_ms\":{},\"last_seen_ms\":{},\"removed_ms\":{},\"removal_reason\":{}}}",
            h16(row.node),
            hex_lower(&row.kid),
            if row.member { "member" } else { "removed" },
            row.generation,
            role_name(row.role),
            row.member_cert_serial,
            if !row.member {
                "null".to_string()
            } else if row.confirmed {
                "\"active\"".to_string()
            } else {
                "\"allowed_unconfirmed\"".to_string()
            },
            row.delivered_ms.is_some(),
            row.model,
            row.hw_rev,
            row.cert_serial,
            row.approved_ms,
            opt(row.delivered_ms),
            opt(row.confirmed_ms),
            opt(row.last_seen_ms),
            opt(row.removed_ms),
            if row.member {
                "null".to_string()
            } else {
                format!("\"{}\"", reason_name(row.removal_reason))
            }
        )
    }

    pub fn members_json(&self, after: Option<u64>, limit: usize, include_removed: bool) -> String {
        let (items, next) = Self::page(
            self.devices
                .iter()
                .filter(|(_, d)| include_removed || d.member),
            after,
            limit,
            Self::member_json,
        );
        format!(
            "{{\"members\":[{items}],\"next_after\":{},\"clock\":\"host_unix_ms\"}}",
            next.map_or_else(|| "null".to_string(), |n| format!("\"{}\"", h16(n)))
        )
    }

    pub fn member_get_json(&self, node: u64) -> Option<String> {
        self.devices
            .get(&node)
            .map(|row| format!("{{\"member\":{}}}", Self::member_json(row)))
    }

    pub fn operation_json(&self, id: u64) -> Option<String> {
        let op = self.operations.get(&id)?;
        let members = self.devices.values().filter(|d| d.member).count();
        Some(match op.kind.as_str() {
            "revoke" => format!(
                "{{\"operation_id\":\"{}\",\"kind\":\"revoke\",\"device_id\":\"{}\",\"generation\":{},\"state\":\"committed\",\"rs_epoch\":{},\"distribution\":{{\"state\":\"not_implemented\",\"reached\":null,\"members\":{members},\"unknown\":{members}}},\"gk_rotation\":{{\"from\":{},\"to\":{},\"state\":\"{}\"}},\"created_ms\":{}}}",
                op_token(op.id),
                h16(op.node),
                op.generation,
                op.rs_epoch,
                op.gk_from,
                op.gk_to,
                if self.gk_active.epoch >= op.gk_to { "active" } else { "staged" },
                op.created_ms
            ),
            _ => {
                let row = self.devices.get(&op.node);
                let state = match row {
                    Some(r) if r.member && r.generation == op.generation && r.confirmed => "confirmed",
                    Some(r) if r.member && r.generation == op.generation && r.delivered_ms.is_some() => {
                        "delivered"
                    }
                    Some(r) if r.generation == op.generation && !r.member => "revoked",
                    _ => "committed",
                };
                format!(
                    "{{\"operation_id\":\"{}\",\"kind\":\"approve\",\"device_id\":\"{}\",\"generation\":{},\"member_cert_serial\":{},\"state\":\"{state}\",\"created_ms\":{}}}",
                    op_token(op.id),
                    h16(op.node),
                    op.generation,
                    op.member_cert_serial,
                    op.created_ms
                )
            }
        })
    }

    /// The latest RRS1 object (for the P6 distribution path and tests).
    pub fn latest_rrs(&mut self) -> Option<Vec<u8>> {
        let snapshot = self.store.load().ok()?;
        snapshot
            .rrs
            .into_iter()
            .max_by_key(|(e, _)| *e)
            .map(|(_, o)| o)
    }
}

/// Splits a join EAD field: exactly one critical `join` item and — when
/// `with_credential` — exactly one critical certificate item; padding
/// (label 0) is skipped, anything else refuses the message.
fn split_join_ead(
    items: &[EadItem],
    join: JoinEad,
    with_credential: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>), &'static str> {
    let mut join_value = None;
    let mut credential = None;
    for item in items {
        if item.is_padding() && item.value.is_none() {
            continue;
        }
        let Some(value) = item.value.clone() else {
            return Err("ead item without value");
        };
        if !item.is_critical() {
            return Err("non-critical ead item");
        }
        let label = item.absolute_label();
        if label == u64::from(join as u32) && join_value.is_none() {
            join_value = Some(value);
        } else if with_credential
            && label == u64::from(JOIN_EAD_CREDENTIAL_LABEL)
            && credential.is_none()
        {
            credential = Some(value);
        } else {
            return Err("unexpected or duplicated ead item");
        }
    }
    let join_value = join_value.ok_or("join ead item missing")?;
    if with_credential && credential.is_none() {
        return Err("certificate ead item missing");
    }
    Ok((join_value, credential))
}

// --- service wrapper ---------------------------------------------------------------------------

/// Thread-safe front of the authority: every entry point runs the
/// authority under its lock, then — with the lock released — hands the
/// outbound relay messages to the transport and returns the events for
/// the caller to append to the daemon's event ring.
pub struct SiteService {
    authority: Mutex<SiteAuthority>,
    transport: Mutex<Option<Arc<dyn JoinTransport>>>,
}

pub type Events = Vec<(u64, String)>;

impl SiteService {
    pub fn new(authority: SiteAuthority) -> Self {
        Self {
            authority: Mutex::new(authority),
            transport: Mutex::new(None),
        }
    }

    pub fn set_transport(&self, transport: Arc<dyn JoinTransport>) {
        *self.transport.lock().expect("transport poisoned") = Some(transport);
    }

    /// Runs `f` on the authority; delivers what it queued.
    pub fn with<R>(&self, f: impl FnOnce(&mut SiteAuthority) -> R) -> (R, Events) {
        let (result, outbound, events) = {
            let mut authority = self.authority.lock().expect("site authority poisoned");
            let result = f(&mut authority);
            (result, authority.take_outbound(), authority.take_events())
        };
        if !outbound.is_empty() {
            let transport = self.transport.lock().expect("transport poisoned").clone();
            if let Some(transport) = transport {
                for message in outbound {
                    transport.deliver(message);
                }
            }
        }
        (result, events)
    }

    pub fn handle_up(&self, up: RelayUp, now_ms: u64) -> Events {
        self.with(|a| a.handle_up(up, now_ms)).1
    }

    pub fn tick(&self, now_ms: u64) -> Events {
        self.with(|a| a.tick(now_ms)).1
    }

    pub fn acl_network(&self) -> u64 {
        self.authority
            .lock()
            .expect("site authority poisoned")
            .acl_network()
    }
}

#[cfg(test)]
mod e2e;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;
