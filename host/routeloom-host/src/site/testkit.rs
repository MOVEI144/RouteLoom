//! Test kit: dev keys for one site and a simulated joining device that
//! speaks the device side of the join — the Rust EDHOC Initiator (byte-exact
//! with libedhoc, protocol/edhoc-interop) plus routeloom-join's device-side
//! checks (SiteCert under the Site CA anchor, SiteOffer ⇔ SiteCert, 02 §10.2
//! `join_allow_verify`, 04 §6.1 `RemovalNotice::verify`). Test keys only.

use routeloom_edhoc::{
    crypto::random_scalar, EadItem, Initiator, LocalCredential, LocalKey, Method, PeerCredential,
    ScalarSigner, SUITE_2,
};
use routeloom_join::{
    dams_exporter_context, join_allow_verify, join_org_hint, JoinEad, JoinIntent, JoinRequest,
    JoinResult, RemovalNotice, SiteOffer, DAMS_SIZE, EXPORTER_LABEL_DAMS,
    JOIN_EAD_CREDENTIAL_LABEL, JOIN_PROFILE_RLJOIN1,
};
use routeloom_provision::credential::credential_kid;
use routeloom_provision::sdkv1::cert::{cert_issue, cert_verify, CertClaims, CertType};
use routeloom_provision::signer::{test_keypair, FileRootSigner, RootSigner};

use super::group_keys::{GroupKeyCommand, GroupKeyTransport};
use super::store::SiteStore;
use super::transport::{AbortReason, InProcessTransport, Outbound, RelayKey, RelayUp};
use super::{Events, SiteAuthority, SiteService, SiteSetup};

pub const SITE: u64 = 0x5173_0000_0000_0042;
pub const NETWORK_LOW: u32 = 0x0A1B_2C3D;
pub const SITE_EPOCH: u32 = 3;
pub const SITE_CA: u64 = 0x05CA_0000_0000_0001;
pub const DEVICE_CA: u64 = 0x0DCA_0000_0000_0001;
pub const GATEWAY: u64 = 0x00A1_0000_0000_0001;

pub fn network() -> u64 {
    (u64::from(SITE_EPOCH) << 32) | u64::from(NETWORK_LOW)
}

pub fn site_ca_pub() -> [u8; 64] {
    test_keypair(0x61).1
}

pub fn sak() -> FileRootSigner {
    FileRootSigner::from_secret(SITE, &test_keypair(0x62).0).unwrap()
}

pub fn device_ca() -> FileRootSigner {
    FileRootSigner::from_secret(DEVICE_CA, &test_keypair(0x63).0).unwrap()
}

pub fn site_cert() -> Vec<u8> {
    let site_ca = FileRootSigner::from_secret(SITE_CA, &test_keypair(0x61).0).unwrap();
    cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: SITE_CA,
            subject: SITE,
            pubkey: test_keypair(0x62).1,
            network_low32: NETWORK_LOW,
            site_epoch: SITE_EPOCH,
            usage: 1,
            serial: 7,
            ..CertClaims::default()
        },
        &site_ca,
    )
    .unwrap()
}

pub fn setup() -> SiteSetup {
    SiteSetup {
        site_cert: site_cert(),
        site_ca_pubkey: Some(site_ca_pub()),
        device_ca_id: DEVICE_CA,
        device_ca_pubkey: test_keypair(0x63).1,
        channel: 1,
        channel_epoch: 1,
        gateways: vec![GATEWAY],
    }
}

pub fn authority(store: Box<dyn SiteStore>, now_ms: u64) -> SiteAuthority {
    SiteAuthority::open(&setup(), Box::new(sak()), store, now_ms).unwrap()
}

/// What a member device keeps in its RLS1 after a verified Allow.
#[derive(Clone, Debug)]
pub struct SiteState {
    pub site: CertClaims,
    pub member: CertClaims,
    pub dams: Vec<u8>,
}

pub struct SimDevice {
    pub node: u64,
    secret: [u8; 32],
    pub pubkey: [u8; 64],
    pub kid: [u8; 32],
    pub dev_cert: Vec<u8>,
    pub capability: u32,
    pub mac: [u8; 6],
    pub site: Option<SiteState>,
    relay: u32,
}

/// Where a join exchange stands after the device's last step.
#[derive(Debug)]
pub enum Outcome {
    /// message_4 carried this result (already checked device-side).
    Result(JoinResult),
    /// An EDHOC error message came back.
    EdhocError(Vec<u8>),
    Aborted(AbortReason),
    /// message_3 was accepted; the authority is waiting for KGuard.
    Waiting,
}

pub struct Exchange {
    initiator: Initiator,
    key: RelayKey,
    site: Option<CertClaims>,
}

impl SimDevice {
    /// A device whose DevCert comes from `ca` (the site's Device CA unless
    /// a test wants a foreign one).
    pub fn with_ca(node: u64, seed: u8, ca: &FileRootSigner) -> Self {
        let (secret, pubkey) = test_keypair(seed);
        let dev_cert = cert_issue(
            &CertClaims {
                cert_type: CertType::Device,
                issuer: ca.root_id(),
                subject: node,
                pubkey,
                model: 17,
                hw_rev: 2,
                serial: u32::from(seed),
                ..CertClaims::default()
            },
            ca,
        )
        .unwrap();
        Self {
            node,
            secret,
            pubkey,
            kid: credential_kid(&pubkey),
            dev_cert,
            capability: routeloom_join::JOIN_CAPABILITY_RELAY,
            mac: [0x02, 0, 0, 0, seed, 1],
            site: None,
            relay: 0,
        }
    }

    pub fn new(node: u64, seed: u8) -> Self {
        Self::with_ca(node, seed, &device_ca())
    }

    fn up(&self, key: RelayKey, step: u8, body: Vec<u8>) -> RelayUp {
        RelayUp {
            key,
            hops: 2,
            step,
            joiner_rssi_dbm: -60,
            body,
        }
    }

    fn outcome_from(&mut self, exchange: &mut Exchange, sent: Vec<Outbound>) -> Outcome {
        for message in sent {
            match message {
                Outbound::Abort { key, reason } if key == exchange.key => {
                    return Outcome::Aborted(reason)
                }
                Outbound::Down(down) if down.key == exchange.key => {
                    if down.step == 5 {
                        return Outcome::EdhocError(down.body);
                    }
                    assert_eq!(down.step, 4, "unexpected step");
                    let ead = exchange
                        .initiator
                        .process_message_4(&down.body)
                        .expect("message_4");
                    assert_eq!(ead.len(), 1);
                    assert_eq!(ead[0].absolute_label(), u64::from(JoinEad::Result as u32));
                    let result =
                        JoinResult::decode(ead[0].value.as_deref().unwrap()).expect("JoinResult");
                    self.apply(exchange, &result);
                    return Outcome::Result(result);
                }
                _ => {}
            }
        }
        Outcome::Waiting
    }

    /// The device-side handling of a verdict (02 §10.2, 04 §6).
    fn apply(&mut self, exchange: &Exchange, result: &JoinResult) {
        match result {
            JoinResult::Allow { .. } => {
                let site = exchange.site.clone().expect("site cert");
                let (member, verified) =
                    join_allow_verify(result, &site, self.node, &self.pubkey, false)
                        .expect("allow");
                assert!(verified, "Allow failed the device-side 02 §10.2 check");
                let context = dams_exporter_context(
                    member.network,
                    self.node,
                    site.subject,
                    &self.kid,
                    &credential_kid(&site.pubkey),
                );
                let dams = exchange
                    .initiator
                    .exporter(EXPORTER_LABEL_DAMS, &context, DAMS_SIZE)
                    .unwrap();
                self.site = Some(SiteState { site, member, dams });
            }
            JoinResult::Removed { removal_notice } => {
                let state = self
                    .site
                    .clone()
                    .expect("a removed device holds site state");
                let (_, verified) = RemovalNotice::verify(
                    removal_notice,
                    &state.site.pubkey,
                    state.site.subject,
                    state.member.network,
                    self.node,
                    state.member.assignment_generation,
                )
                .expect("removal notice");
                assert!(verified, "RemovalNotice failed the device-side check");
                // 04 §6.4: erase the site state, keep the identity.
                self.site = None;
            }
            _ => {}
        }
    }

    /// message_1 … message_3; message_4 if the authority answered at once.
    pub fn start(
        &mut self,
        service: &SiteService,
        transport: &InProcessTransport,
        now_ms: u64,
    ) -> (Exchange, Outcome, Events) {
        self.relay += 1;
        let key = RelayKey {
            gateway: GATEWAY,
            proxy: 0x00A1_0000_0000_0777,
            relay_id: self.relay,
            joiner_mac: self.mac,
        };
        let mut exchange = Exchange {
            initiator: Initiator::new(
                Method::SignatureSignature,
                vec![SUITE_2],
                vec![0x11, 0x22, 0x33, 0x44],
            )
            .unwrap(),
            key,
            site: None,
        };
        let intent = JoinIntent {
            org_hint: join_org_hint(&site_ca_pub()),
            profile_bits: JOIN_PROFILE_RLJOIN1,
        }
        .encode()
        .unwrap();
        let m1 = exchange
            .initiator
            .compose_message_1(
                random_scalar().unwrap(),
                &[EadItem::critical(JoinEad::Intent as u32, intent.to_vec())],
            )
            .unwrap();
        let mut events = service.handle_up(self.up(key, 1, m1), now_ms);
        let sent = transport.take();
        let Some(m2) = sent.iter().find_map(|m| match m {
            Outbound::Down(d) if d.key == key && d.step == 2 => Some(d.body.clone()),
            _ => None,
        }) else {
            let outcome = self.outcome_from(&mut exchange, sent);
            return (exchange, outcome, events);
        };
        // Device side of message_2: SiteCert by value, anchored at the Site
        // CA; the SiteOffer must match it (02 §6.3).
        let mut site_claims = None;
        exchange
            .initiator
            .process_message_2(&m2, |kid, ead| {
                let mut offer = None;
                let mut cert = None;
                for item in ead {
                    match item.absolute_label() {
                        l if l == u64::from(JoinEad::Offer as u32) => offer = item.value.clone(),
                        l if l == u64::from(JOIN_EAD_CREDENTIAL_LABEL) => cert = item.value.clone(),
                        _ => return Err("unexpected EAD_2 item".into()),
                    }
                }
                let cert = cert.ok_or("no SiteCert")?;
                let (claims, ok) = cert_verify(&cert, &site_ca_pub()).map_err(|e| e.to_string())?;
                if !ok
                    || claims.cert_type != CertType::Site
                    || credential_kid(&claims.pubkey) != kid
                {
                    return Err("SiteCert not anchored".into());
                }
                SiteOffer::decode(&offer.ok_or("no SiteOffer")?)
                    .and_then(|o| o.matches_site_cert(&claims))
                    .map_err(|e| e.to_string())?;
                let public_key = claims.pubkey;
                site_claims = Some(claims);
                Ok(PeerCredential {
                    cred: cert,
                    public_key,
                })
            })
            .expect("message_2");
        exchange.site = site_claims;
        let (last_site, last_generation) = self
            .site
            .as_ref()
            .map_or((0, 0), |s| (s.site.subject, s.member.assignment_generation));
        let request = JoinRequest {
            model: 17,
            fw_version: 0x0104_0000,
            capability: self.capability,
            requested_role: 1,
            last_site_id: last_site,
            last_generation,
        }
        .encode()
        .unwrap();
        let signer = ScalarSigner(self.secret);
        let local = LocalCredential {
            kid: &self.kid,
            cred: &self.dev_cert,
            key: LocalKey::Signature(&signer),
        };
        let m3 = exchange
            .initiator
            .compose_message_3(
                &local,
                &[
                    EadItem::critical(JoinEad::Request as u32, request.to_vec()),
                    EadItem::critical(JOIN_EAD_CREDENTIAL_LABEL, self.dev_cert.clone()),
                ],
            )
            .unwrap();
        events.extend(service.handle_up(self.up(key, 3, m3), now_ms));
        let sent = transport.take();
        let outcome = self.outcome_from(&mut exchange, sent);
        (exchange, outcome, events)
    }

    /// Collects message_4 after the authority decided (decide / tick).
    pub fn finish(&mut self, exchange: &mut Exchange, transport: &InProcessTransport) -> Outcome {
        let sent = transport.take();
        self.outcome_from(exchange, sent)
    }

    /// Runs a whole attempt that is expected to be answered at once.
    pub fn attempt(
        &mut self,
        service: &SiteService,
        transport: &InProcessTransport,
        now_ms: u64,
    ) -> (Outcome, Events) {
        let (_, outcome, events) = self.start(service, transport, now_ms);
        (outcome, events)
    }
}

/// Kinds of the events in `events`, in order.
pub fn kinds(events: &Events) -> Vec<String> {
    events
        .iter()
        .map(|(_, fields)| {
            let json = routeloom_json::parse(&format!("{{{fields}}}")).expect("event JSON");
            json.get("kind").unwrap().as_str().unwrap().to_string()
        })
        .collect()
}

/// The `join_request_id` of the first `join.request` event.
pub fn request_id(events: &Events) -> Option<u64> {
    events.iter().find_map(|(_, fields)| {
        let json = routeloom_json::parse(&format!("{{{fields}}}")).ok()?;
        (json.get("kind")?.as_str()? == "join.request")
            .then(|| super::records::parse_request_token(json.get("join_request_id")?.as_str()?))
            .flatten()
    })
}

/// Fake authority-channel transport (§6.2 seam): a configurable ready-set
/// plus the sent-command log. The PR1 channel layer replaces it.
pub struct FakeGroupKeyTransport {
    ready: std::sync::Mutex<std::collections::HashSet<u64>>,
    sent: std::sync::Mutex<Vec<GroupKeyCommand>>,
}

impl FakeGroupKeyTransport {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            ready: std::sync::Mutex::new(std::collections::HashSet::new()),
            sent: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub fn set_ready(&self, node: u64, ready: bool) {
        let mut set = self.ready.lock().expect("gk fake poisoned");
        if ready {
            set.insert(node);
        } else {
            set.remove(&node);
        }
    }

    /// Everything sent since the last call.
    pub fn take(&self) -> Vec<GroupKeyCommand> {
        std::mem::take(&mut *self.sent.lock().expect("gk fake poisoned"))
    }
}

impl GroupKeyTransport for FakeGroupKeyTransport {
    fn channel_ready(&self, node: u64) -> bool {
        self.ready.lock().expect("gk fake poisoned").contains(&node)
    }

    fn send(&self, command: GroupKeyCommand) {
        self.sent.lock().expect("gk fake poisoned").push(command);
    }
}
