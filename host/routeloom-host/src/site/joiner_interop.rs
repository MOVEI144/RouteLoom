//! Live E2E (design P3-4 §10.2): the real C++ Joiner FSM
//! (`tests/cpp/joiner_interop_peer.cpp`, real Joiner + Link + stores on
//! fake radio/flash, real Proxy + Gateway per site) against two real Rust
//! Site Authorities (`SiteService` on SQLite, API1 socket, KGuardMock).
//!
//! This is the process-interop complement of `site::e2e`, which drives the
//! same authority with a Rust `SimDevice`: here the EDHOC Initiator, the
//! scan/candidate FSM, the RLS1 commit + readback and the MemberReady
//! action are all the portable C++ implementation, while decisions,
//! the durable ledger and the MemberCert/SitePackage/DAMS come from the
//! production Rust code. USB daemon wiring, MeshNode and real radio are
//! out of scope, exactly like the C++ two-site simulator.
//!
//! The peer path comes from `ROUTELOOM_JOINER_PEER` and a missing
//! executable is a hard failure, never a skip (§10.2 item 6); the
//! `joiner-interop` CI job builds the peer first and the general `rust`
//! job filters this module out.
//!
//! Time: the test owns one virtual clock (`t0` = real `now_ms` at start,
//! so API1's real-time stamps stay near the authority's virtual stamps).
//! Every step sends `TICK(now)` to the peer, routes the relay ups through
//! `handle_up`, runs `tick` on both authorities, forwards the downs and
//! serves KGuard over the sockets — all within the same virtual
//! millisecond, so no decision timeout can fire spuriously.
//!
//! The test adapter rule (§10.2 item 4): only `phase == EdhocMessage (4)`
//! crosses the pipe. Anything else — and any object the shared
//! `routeloom-protocol` codec rejects — fails the test. Abort reasons are
//! mapped by meaning, never cast: the host `AbortReason` and the relay
//! `RelayStatusCode` disagree numerically (host `Timeout = 3` is relay
//! `Busy = 3`, which would lie).

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use routeloom_client::api1::RouteLoomTransport;
use routeloom_client::site::{Assignment, Decision, KGuardMock, Role, SiteAdmin};
use routeloom_protocol::join_relay::{
    RelayBody, RelayDirection, RelayHeader, RelayObject, RelayState, RelayStatusCode, PHASE_EDHOC,
    RELAY_OBJECT_MAX,
};
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::{test_keypair, FileRootSigner, RootSigner};

use super::store::SqliteSiteStore;
use super::testkit;
use super::transport::{AbortReason, DownStatus, InProcessTransport, Outbound, RelayKey, RelayUp};
use super::{SiteAuthority, SiteService, SiteSetup};
use crate::acl::Acl;
use crate::{now_ms, serve_client, DeviceSession, State};

// --- Second site ---------------------------------------------------------------
// Same Site CA (one org_hint, like the C++ sim), separate site/SAK/GK/ledger.

const SITE_B: u64 = 0x5173_0000_0000_0043;
const NETWORK_B_LOW: u32 = 0x0B1C_2D3E;
const GATEWAY_B: u64 = 0x00A1_0000_0000_0002;
const SITE_B_SEED: u8 = 0x72;

const DEVICE_NODE: u64 = 0x00A1_0000_0000_1234;
const DEVICE_SEED: u8 = 0x71;
const DEVICE_MAC: [u8; 6] = [0x02, 0, 0, 0, DEVICE_SEED, 1];

fn network_b() -> u64 {
    (u64::from(testkit::SITE_EPOCH) << 32) | u64::from(NETWORK_B_LOW)
}

fn sak_b() -> FileRootSigner {
    FileRootSigner::from_secret(SITE_B, &test_keypair(SITE_B_SEED).0).unwrap()
}

fn site_b_cert() -> Vec<u8> {
    let site_ca = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: testkit::SITE_CA,
            subject: SITE_B,
            pubkey: test_keypair(SITE_B_SEED).1,
            network_low32: NETWORK_B_LOW,
            site_epoch: testkit::SITE_EPOCH,
            usage: 1,
            serial: 9,
            ..CertClaims::default()
        },
        &site_ca,
    )
    .unwrap()
}

fn setup_b() -> SiteSetup {
    SiteSetup {
        site_cert: site_b_cert(),
        site_ca_pubkey: Some(test_keypair(0x61).1),
        device_ca_id: testkit::DEVICE_CA,
        device_ca_pubkey: test_keypair(0x63).1,
        channel: 1,
        channel_epoch: 1,
        gateways: vec![GATEWAY_B],
    }
}

struct DeviceKeys {
    priv_hex: String,
    pub_hex: String,
    cert_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn device_keys() -> DeviceKeys {
    let ca = testkit::device_ca();
    let (secret, pubkey) = test_keypair(DEVICE_SEED);
    let cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Device,
            issuer: ca.root_id(),
            subject: DEVICE_NODE,
            pubkey,
            model: 17,
            hw_rev: 2,
            serial: u32::from(DEVICE_SEED),
            ..CertClaims::default()
        },
        &ca,
    )
    .unwrap();
    DeviceKeys {
        priv_hex: hex(&secret),
        pub_hex: hex(&pubkey),
        cert_hex: hex(&cert),
    }
}

// --- Peer process --------------------------------------------------------------

const RPC_MAX: usize = 1100;

struct PeerUp {
    site: u8,
    proxy: u64,
    hops: u8,
    object: Vec<u8>,
}

#[derive(Debug)]
struct PeerAbort {
    site: u8,
    proxy: u64,
    relay_id: u32,
    reason: u8,
}

/// `S` observation, tag excluded.
struct Snap {
    state: u8,
    action_pending: bool,
    pending_action: u8,
    store_site: u64,
    store_gen: u32,
    site_writes: u16,
    last_write_at: u64,
    last_read_at: u64,
    zt_sends: u32,
    terminal_at: u64,
    terminal_kind: u8,
}

/// `M` observation: stored certs plus the DAMS digest (never the key).
struct Member {
    site_cert: Vec<u8>,
    member_cert: Vec<u8>,
    dams_digest: [u8; 32],
}

struct Tick {
    ups: Vec<PeerUp>,
    aborts: Vec<PeerAbort>,
    snap: Snap,
    member: Member,
}

fn get_u16(payload: &[u8], pos: &mut usize) -> u16 {
    let value = u16::from_le_bytes([payload[*pos], payload[*pos + 1]]);
    *pos += 2;
    value
}

fn get_u32(payload: &[u8], pos: &mut usize) -> u32 {
    let value = u32::from_le_bytes([
        payload[*pos],
        payload[*pos + 1],
        payload[*pos + 2],
        payload[*pos + 3],
    ]);
    *pos += 4;
    value
}

fn get_u64(payload: &[u8], pos: &mut usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&payload[*pos..*pos + 8]);
    *pos += 8;
    u64::from_le_bytes(raw)
}

struct Peer {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Peer {
    fn spawn(t0: u64, seed: u64, flash: Option<&std::path::Path>) -> Self {
        let path = std::env::var("ROUTELOOM_JOINER_PEER")
            .expect("ROUTELOOM_JOINER_PEER must name routeloom_joiner_interop_peer");
        let keys = device_keys();
        let site_ca_pub = test_keypair(0x61).1;
        let mut command = Command::new(&path);
        command
            .arg("--node")
            .arg(format!("{DEVICE_NODE:#x}"))
            .arg("--mac")
            .arg(hex(&DEVICE_MAC))
            .arg("--dev-priv")
            .arg(&keys.priv_hex)
            .arg("--dev-pub")
            .arg(&keys.pub_hex)
            .arg("--dev-cert")
            .arg(&keys.cert_hex)
            .arg("--site-ca-id")
            .arg(format!("{:#x}", testkit::SITE_CA))
            .arg("--site-ca-pub")
            .arg(hex(&site_ca_pub))
            .arg("--fw")
            .arg("0x01040000")
            .arg("--cap")
            .arg("7")
            .arg("--role")
            .arg("1")
            .arg("--t0")
            .arg(format!("{t0}"))
            .arg("--seed")
            .arg(format!("{seed}"))
            .arg("--site")
            .arg(format!(
                "{:#x},{:#x},{:#x},{},{:#x},6,-30,1",
                testkit::SITE,
                testkit::network(),
                testkit::GATEWAY,
                hex(&[0x02, 0, 0, 0, 0x0A, 1]),
                0x00A1_0000_0000_0A01u64,
            ))
            .arg("--site")
            .arg(format!(
                "{SITE_B:#x},{:#x},{GATEWAY_B:#x},{},{:#x},11,-60,1",
                network_b(),
                hex(&[0x02, 0, 0, 0, 0x0B, 1]),
                0x00A1_0000_0000_0B01u64,
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(file) = flash {
            command.arg("--flash").arg(file);
        }
        let mut child = command.spawn().expect("spawn joiner interop peer");
        let stdin = child.stdin.take().expect("peer stdin");
        let stdout = child.stdout.take().expect("peer stdout");
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, payload: &[u8]) {
        assert!(!payload.is_empty() && payload.len() <= RPC_MAX, "rpc bound");
        let head = (payload.len() as u16).to_le_bytes();
        self.stdin.write_all(&head).expect("peer input open");
        self.stdin.write_all(payload).expect("peer input open");
        self.stdin.flush().expect("peer input open");
    }

    fn recv(&mut self) -> Vec<u8> {
        let mut head = [0u8; 2];
        self.stdout.read_exact(&mut head).expect("peer alive");
        let length = usize::from(u16::from_le_bytes(head));
        assert!((1..=RPC_MAX).contains(&length), "rpc bound");
        let mut payload = vec![0u8; length];
        self.stdout.read_exact(&mut payload).expect("peer alive");
        payload
    }

    fn tick(&mut self, now: u64) -> Tick {
        let mut command = vec![b'T'];
        command.extend_from_slice(&now.to_le_bytes());
        self.send(&command);
        let mut tick = Tick {
            ups: Vec::new(),
            aborts: Vec::new(),
            snap: Snap {
                state: 0,
                action_pending: false,
                pending_action: 0,
                store_site: 0,
                store_gen: 0,
                site_writes: 0,
                last_write_at: 0,
                last_read_at: 0,
                zt_sends: 0,
                terminal_at: 0,
                terminal_kind: 0,
            },
            member: Member {
                site_cert: Vec::new(),
                member_cert: Vec::new(),
                dams_digest: [0; 32],
            },
        };
        let mut done = false;
        while !done {
            let payload = self.recv();
            match payload[0] {
                b'U' => {
                    let mut pos = 1;
                    let site = payload[pos];
                    pos += 1;
                    let proxy = get_u64(&payload, &mut pos);
                    let hops = payload[pos];
                    pos += 1;
                    tick.ups.push(PeerUp {
                        site,
                        proxy,
                        hops,
                        object: payload[pos..].to_vec(),
                    });
                }
                b'A' => {
                    let mut pos = 1;
                    let site = payload[pos];
                    pos += 1;
                    let proxy = get_u64(&payload, &mut pos);
                    let relay_id = get_u32(&payload, &mut pos);
                    tick.aborts.push(PeerAbort {
                        site,
                        proxy,
                        relay_id,
                        reason: payload[pos],
                    });
                }
                b'S' => {
                    assert_eq!(payload.len(), 47, "S shape");
                    let mut pos = 1;
                    tick.snap.state = payload[pos];
                    pos += 1;
                    tick.snap.action_pending = payload[pos] != 0;
                    pos += 1;
                    tick.snap.pending_action = payload[pos];
                    pos += 1;
                    tick.snap.store_site = get_u64(&payload, &mut pos);
                    tick.snap.store_gen = get_u32(&payload, &mut pos);
                    tick.snap.site_writes = get_u16(&payload, &mut pos);
                    tick.snap.last_write_at = get_u64(&payload, &mut pos);
                    tick.snap.last_read_at = get_u64(&payload, &mut pos);
                    tick.snap.zt_sends = get_u32(&payload, &mut pos);
                    tick.snap.terminal_at = get_u64(&payload, &mut pos);
                    tick.snap.terminal_kind = payload[pos];
                }
                b'M' => {
                    let mut pos = 1;
                    let site_len = usize::from(get_u16(&payload, &mut pos));
                    tick.member.site_cert = payload[pos..pos + site_len].to_vec();
                    pos += site_len;
                    let member_len = usize::from(get_u16(&payload, &mut pos));
                    tick.member.member_cert = payload[pos..pos + member_len].to_vec();
                    pos += member_len;
                    tick.member
                        .dams_digest
                        .copy_from_slice(&payload[pos..pos + 32]);
                }
                b'D' => done = true,
                b'E' => panic!("peer fatal: {}", String::from_utf8_lossy(&payload[1..])),
                tag => panic!("unknown peer tag {tag}"),
            }
        }
        tick
    }

    fn send_down(&mut self, site: u8, to_proxy: u64, object: &[u8]) {
        assert!(object.len() <= RELAY_OBJECT_MAX, "relay object bound");
        let mut command = vec![b'W', site];
        command.extend_from_slice(&to_proxy.to_le_bytes());
        command.extend_from_slice(object);
        self.send(&command);
    }

    /// The 4 KB flash image (identity slots, then site slots) for the
    /// power-cut handover: only these bytes cross into the respawn.
    fn dump_flash(&mut self) -> Vec<u8> {
        self.send(b"P");
        let mut image = Vec::with_capacity(4096);
        for _ in 0..4 {
            let payload = self.recv();
            assert_eq!(payload[0], b'P', "flash slot reply");
            assert_eq!(payload.len(), 3 + 1024, "slot image");
            image.extend_from_slice(&payload[3..]);
        }
        image
    }
}

// --- Sites ---------------------------------------------------------------------

struct InteropSite {
    service: Arc<SiteService>,
    transport: Arc<InProcessTransport>,
    link: RouteLoomTransport,
    kguard: KGuardMock,
    gateway: u64,
    dir: std::path::PathBuf,
}

impl Drop for InteropSite {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl InteropSite {
    fn start(
        tag: &str,
        setup: &SiteSetup,
        sak: FileRootSigner,
        gateway: u64,
        network_low: u32,
        now: u64,
    ) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-joiner-interop-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SqliteSiteStore::open(&dir.join("site.db")).unwrap();
        let authority = SiteAuthority::open(setup, Box::new(sak), Box::new(store), now).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let acl = Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"{network_low:016x}\":[\"MEMBERSHIP_READ\",\"MEMBERSHIP_DECIDE\",\"MEMBERSHIP_ADMIN\"]}}}},\"7\":{{\"networks\":{{\"*\":[\"MEMBERSHIP_READ\"]}}}}}}}}",
        ))
        .unwrap();
        let service = Arc::new(SiteService::new(authority));
        let transport = InProcessTransport::new();
        service.set_transport(transport.clone());
        let state = Arc::new(State {
            acl,
            site: Some(Arc::clone(&service)),
            ..State::default()
        });
        let socket = dir.join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (outbound_tx, _outbound_rx) = mpsc::sync_channel(64);
        let accept_state = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let uid = routeloom_peercred::peer_uid(&stream).ok();
                let state = Arc::clone(&accept_state);
                let outbound = outbound_tx.clone();
                thread::spawn(move || {
                    let _ = serve_client(
                        stream,
                        state,
                        outbound,
                        0,
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(Mutex::new(DeviceSession::new())),
                        uid,
                    );
                });
            }
        });
        let link = RouteLoomTransport::new(&socket, u64::from(network_low));
        Self {
            service,
            transport,
            link,
            kguard: KGuardMock::default(),
            gateway,
            dir,
        }
    }

    fn site_a(tag: &str, now: u64) -> Self {
        Self::start(
            &format!("{tag}-a"),
            &testkit::setup(),
            testkit::sak(),
            testkit::GATEWAY,
            testkit::NETWORK_LOW,
            now,
        )
    }

    fn site_b(tag: &str, now: u64) -> Self {
        Self::start(
            &format!("{tag}-b"),
            &setup_b(),
            sak_b(),
            GATEWAY_B,
            NETWORK_B_LOW,
            now,
        )
    }
}

// --- Driver --------------------------------------------------------------------

/// Host abort → relay abort, mapped by meaning (§10.2 item 4). The two
/// enums share no values: `Busy` is the only retryable hint, everything
/// else ends the relay, and an unreachable authority must read as such
/// on the device — never as `Busy`.
fn map_abort(reason: AbortReason) -> (RelayStatusCode, u32) {
    match reason {
        AbortReason::Busy => (RelayStatusCode::Busy, 1000),
        AbortReason::UnknownRelay | AbortReason::Timeout => (RelayStatusCode::Aborted, 0),
        AbortReason::AuthorityError => (RelayStatusCode::AuthorityUnreachable, 0),
    }
}

fn down_object(key: &RelayKey, step: u8, status: DownStatus, body: Vec<u8>) -> Vec<u8> {
    RelayObject {
        header: RelayHeader {
            dir: RelayDirection::Down,
            relay_id: key.relay_id,
            proxy: key.proxy,
            joiner_mac: key.joiner_mac,
            phase: PHASE_EDHOC,
            step,
            state: if status == DownStatus::Final {
                RelayState::Final
            } else {
                RelayState::Continue
            },
            joiner_rssi_dbm: 0,
        },
        body: RelayBody::Message(body),
    }
    .encode()
    .expect("down object encodes")
}

fn abort_object(key: &RelayKey, reason: AbortReason) -> Vec<u8> {
    let (status, retry_after_ms) = map_abort(reason);
    RelayObject {
        header: RelayHeader {
            dir: RelayDirection::Down,
            relay_id: key.relay_id,
            proxy: key.proxy,
            joiner_mac: key.joiner_mac,
            phase: PHASE_EDHOC,
            step: 2,
            state: RelayState::Abort,
            joiner_rssi_dbm: 0,
        },
        body: RelayBody::Abort {
            status,
            retry_after_ms,
        },
    }
    .encode()
    .expect("abort object encodes")
}

struct World {
    peer: Peer,
    sites: [InteropSite; 2],
    now: u64,
    /// (site, decision) in serve order.
    decisions: Vec<(u8, Decision)>,
    /// (site, m4 forward time, durable row delivered_ms) for Allow forwards.
    allow_forwards: Vec<(u8, u64, u64)>,
    aborts_seen: Vec<PeerAbort>,
    ups_seen: u64,
}

impl World {
    fn start(tag: &str, seed: u64) -> Self {
        let now = now_ms();
        Self {
            peer: Peer::spawn(now, seed, None),
            sites: [InteropSite::site_a(tag, now), InteropSite::site_b(tag, now)],
            now,
            decisions: Vec::new(),
            allow_forwards: Vec::new(),
            aborts_seen: Vec::new(),
            ups_seen: 0,
        }
    }

    fn swap_peer(&mut self, t0: u64, seed: u64, flash: &std::path::Path) {
        self.now = t0;
        self.peer = Peer::spawn(t0, seed, Some(flash));
    }

    fn route_up(&mut self, up: &PeerUp) {
        let site_idx = usize::from(up.site);
        assert!(site_idx < 2, "up from a known site");
        let object = RelayObject::decode(&up.object).expect("relay object decodes");
        object.validate().expect("relay object valid");
        assert_eq!(
            object.header.phase, PHASE_EDHOC,
            "test adapter: EDHOC phase only"
        );
        assert_eq!(object.header.dir, RelayDirection::Up);
        assert_eq!(up.proxy, object.header.proxy, "proxy agrees");
        let RelayBody::Message(body) = object.body.clone() else {
            panic!("an up object carries a message");
        };
        let relay = RelayUp {
            key: RelayKey {
                // Gateway identity comes from the fixture, not the wire.
                gateway: self.sites[site_idx].gateway,
                proxy: object.header.proxy,
                relay_id: object.header.relay_id,
                joiner_mac: object.header.joiner_mac,
            },
            hops: up.hops,
            step: object.header.step,
            joiner_rssi_dbm: object.header.joiner_rssi_dbm,
            body,
        };
        assert_eq!(relay.key.joiner_mac, DEVICE_MAC, "our device only");
        self.sites[site_idx].service.handle_up(relay, self.now);
        self.drain(site_idx);
    }

    fn drain(&mut self, site_idx: usize) {
        let site = site_idx as u8;
        for outbound in self.sites[site_idx].transport.take() {
            match outbound {
                Outbound::Down(down) => {
                    // The JoinResult rides encrypted inside the m4, so the
                    // Allow detection keys on the committed row KGuard's
                    // decision produced: an m4 for a decided-Allow device
                    // must find its DAMS + delivered_ms already durable.
                    if down.step == 4 && down.status == DownStatus::Final {
                        let allowed_here = self
                            .decisions
                            .iter()
                            .any(|(s, d)| *s == site && matches!(d, Decision::Allow(_)));
                        let (row, durable) = self.sites[site_idx]
                            .service
                            .with(|a| {
                                let row = a.devices.get(&DEVICE_NODE).cloned();
                                let durable = a
                                    .store
                                    .load()
                                    .expect("read committed member row")
                                    .devices
                                    .into_iter()
                                    .find(|member| member.node == DEVICE_NODE);
                                (row, durable)
                            })
                            .0;
                        if allowed_here {
                            let row = row.expect("allow committed before its m4");
                            assert!(row.member, "allow row is a member");
                            assert_ne!(row.dams, [0; 32], "DAMS stored with the delivery");
                            let delivered = row
                                .delivered_ms
                                .expect("delivered_ms stored with the delivery");
                            let durable = durable.expect("allow persisted before its m4");
                            assert_eq!(durable.delivered_ms, Some(delivered));
                            assert_eq!(durable.dams, row.dams);
                            self.allow_forwards.push((site, self.now, delivered));
                        } else {
                            assert!(
                                row.as_ref().is_none_or(|r| !r.member),
                                "no member row without an Allow"
                            );
                        }
                    }
                    let bytes = down_object(&down.key, down.step, down.status, down.body.clone());
                    self.peer.send_down(site, down.key.proxy, &bytes);
                }
                Outbound::Abort { key, reason } => {
                    let bytes = abort_object(&key, reason);
                    self.peer.send_down(site, key.proxy, &bytes);
                }
            }
        }
    }

    fn serve_kguard(&mut self) {
        for index in 0..2 {
            let served = self.sites[index]
                .kguard
                .serve_once(&self.sites[index].link)
                .unwrap();
            for (request, decision, _) in served {
                assert_eq!(request.device, DEVICE_NODE, "our device only");
                self.decisions.push((index as u8, decision));
            }
            self.drain(index);
        }
    }

    /// One virtual step: peer pump, up routing, authority ticks, KGuard.
    fn step(&mut self, dt_ms: u64) -> Tick {
        self.now += dt_ms;
        let tick = self.peer.tick(self.now);
        self.ups_seen += tick.ups.len() as u64;
        for up in &tick.ups {
            self.route_up(up);
        }
        for index in 0..2 {
            self.sites[index]
                .service
                .tick(super::group_keys::HostTime::sync(self.now));
            self.drain(index);
        }
        self.serve_kguard();
        for abort in &tick.aborts {
            self.aborts_seen.push(PeerAbort {
                site: abort.site,
                proxy: abort.proxy,
                relay_id: abort.relay_id,
                reason: abort.reason,
            });
        }
        tick
    }

    fn pump_until(&mut self, budget_ticks: u32, done: impl Fn(&Tick) -> bool) -> Tick {
        let mut tick = self.step(25);
        for _ in 1..budget_ticks {
            if done(&tick) {
                return tick;
            }
            tick = self.step(25);
        }
        assert!(done(&tick), "pump budget exhausted");
        tick
    }

    fn member_row(&self, site: usize) -> Option<super::store::DeviceRow> {
        self.sites[site]
            .service
            .with(|a| a.devices.get(&DEVICE_NODE).cloned())
            .0
    }

    /// DAMS digest + cert bytes: the C++ RLS1 against the Rust ledger.
    fn check_member_material(&self, site: usize, member: &Member) {
        let row = self
            .member_row(site)
            .expect("member row on the allowing site");
        assert!(row.member);
        assert_eq!(sha256(&row.dams), member.dams_digest, "DAMS agrees");
        let expected_site = if site == 0 {
            testkit::site_cert()
        } else {
            site_b_cert()
        };
        assert_eq!(member.site_cert, expected_site, "stored SiteCert");
        assert_eq!(member.member_cert, row.member_cert, "stored MemberCert");
    }
}

// C++ `JoinActionKind` (sdkv1_joiner.hpp): None 0, ChangeChannel 1,
// MemberReady 2, RemovalRequired 3, RecoveryRequired 4.
const MEMBER_READY: u8 = 2;

fn check_terminal(snap: &Snap, kind: u8) {
    // C++ `JoinState::Stopped = 0`: a terminal action never sits on Stopped.
    assert_ne!(snap.state, 0, "the FSM left Stopped");
    assert!(snap.action_pending, "terminal action pending");
    assert_eq!(snap.pending_action, kind, "terminal action kind");
    assert_ne!(snap.terminal_at, 0, "terminal action stamped");
    // RLS1 commit < readback <= MemberReady (the C++ op-log stamps).
    assert_ne!(snap.last_write_at, 0, "RLS1 sealed");
    assert!(
        snap.last_write_at <= snap.last_read_at,
        "commit precedes the readback"
    );
    assert!(
        snap.last_read_at <= snap.terminal_at,
        "readback precedes MemberReady"
    );
}

/// A member boot issues MemberReady from the sealed RLS1 without
/// writing flash: reads only, then the terminal action.
fn check_member_boot(snap: &Snap) {
    assert_ne!(snap.state, 0, "the FSM left Stopped");
    assert!(snap.action_pending, "terminal action pending");
    assert_eq!(snap.pending_action, MEMBER_READY, "MemberReady again");
    assert_ne!(snap.terminal_at, 0, "terminal action stamped");
    assert_eq!(snap.last_write_at, 0, "a member boot writes nothing");
    assert_ne!(snap.last_read_at, 0, "the RLS1 was read");
    assert!(
        snap.last_read_at <= snap.terminal_at,
        "the read precedes MemberReady"
    );
}

// --- Tests ---------------------------------------------------------------------

/// V1-J01 shape: full EDHOC through the pipe, KGuard Allow, durable
/// commit before the m4, RLS1 + DAMS + certs agreeing, MemberReady, and
/// radio silence afterwards.
#[test]
fn cpp_joiner_allows_through_the_rust_authority() {
    let mut world = World::start("allow", 0xA110);
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    let tick = world.pump_until(6000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    assert_eq!(tick.snap.store_site, testkit::SITE);
    assert_eq!(tick.snap.store_gen, 1);
    assert_eq!(world.allow_forwards.len(), 1);
    assert_eq!(world.allow_forwards[0].0, 0);
    world.check_member_material(0, &tick.member);
    assert!(
        world.aborts_seen.is_empty(),
        "no relay aborts: {:?}",
        world.aborts_seen
    );

    let member = world.sites[0]
        .link
        .member(DEVICE_NODE)
        .unwrap()
        .expect("member listed");
    assert!(member.member && member.delivered);
    assert_eq!(member.generation, 1);
    let discovered = world.sites[0].link.discovered().unwrap();
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].device, DEVICE_NODE);
    assert_eq!(discovered[0].model, 17);
    assert_eq!(discovered[0].last_verdict, "allowed");
    // Site B never saw the device.
    assert!(world.member_row(1).is_none());
    assert!(world.sites[1].link.discovered().unwrap().is_empty());

    // Silence after Ready: a 30 s jump carries no ups and no ZT frames.
    let sends = tick.snap.zt_sends;
    world.now += 30_000;
    let quiet = world.peer.tick(world.now);
    assert!(quiet.ups.is_empty(), "no join traffic after Ready");
    assert_eq!(quiet.snap.zt_sends, sends, "no ZT frames after Ready");
    assert!(quiet.snap.action_pending, "terminal action still held");
}

/// V1-J04 shape: the stronger site denies (not_here), the device takes
/// the weaker site's Allow, and nothing of site A is ever stored.
#[test]
fn deny_on_a_falls_over_to_allow_on_b() {
    let mut world = World::start("deny", 0xDE17);
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Elsewhere);
    world.sites[1]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    let tick = world.pump_until(8000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    assert_eq!(tick.snap.store_site, SITE_B);
    assert_eq!(tick.snap.store_gen, 1);
    assert_eq!(world.allow_forwards.len(), 1);
    assert_eq!(world.allow_forwards[0].0, 1);
    world.check_member_material(1, &tick.member);

    assert!(
        world
            .decisions
            .iter()
            .any(|(s, d)| *s == 0 && matches!(d, Decision::DenyNotHere)),
        "site A denied not_here"
    );
    assert!(world.member_row(0).is_none(), "no member row on A");
    let discovered_a = world.sites[0].link.discovered().unwrap();
    assert_eq!(discovered_a.len(), 1);
    assert_eq!(discovered_a[0].last_verdict, "not_here");
    assert!(
        world.aborts_seen.is_empty(),
        "no relay aborts: {:?}",
        world.aborts_seen
    );
}

/// V1-J05 shape (single site, API path): PendingAssignment first — no
/// member row, no flash commit — then the KGuard assignment lands and
/// the retry's full EDHOC completes the join.
#[test]
fn pending_then_kguard_allow() {
    let mut world = World::start("pending", 0x9E17);
    world.sites[0].kguard.pending_retry_s = 30;
    // The first attempt ends in Pending; the device backs off quietly.
    for _ in 0..6000 {
        world.step(25);
        if world
            .decisions
            .iter()
            .any(|(s, d)| *s == 0 && matches!(d, Decision::Pending { .. }))
        {
            break;
        }
    }
    assert!(
        world
            .decisions
            .iter()
            .any(|(s, d)| *s == 0 && matches!(d, Decision::Pending { .. })),
        "a Pending decision landed"
    );
    assert!(world.member_row(0).is_none(), "pending commits nothing");
    assert!(world.allow_forwards.is_empty());
    // The assignment lands; the retry joins.
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    let tick = world.pump_until(8000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    assert_eq!(tick.snap.store_site, testkit::SITE);
    assert_eq!(tick.snap.store_gen, 1);
    assert_eq!(world.allow_forwards.len(), 1);
    world.check_member_material(0, &tick.member);
}

/// Power cut after commit: only the 4 KB flash image crosses into the
/// respawn, which boots as a member with no join traffic and identical
/// RLS1 bytes.
#[test]
fn power_cut_after_commit_boots_as_member() {
    let mut world = World::start("powercut", 0xC07);
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    let tick = world.pump_until(6000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    let before = world.peer.dump_flash();
    let member_before = tick.member.member_cert.clone();
    let dams_before = tick.member.dams_digest;
    let dir = world.sites[0].dir.clone();
    let flash_path = dir.join("flash.bin");
    std::fs::write(&flash_path, &before).unwrap();

    world.swap_peer(world.now + 1000, 0xC08, &flash_path);
    let ups_at_boot = world.ups_seen;
    let tick = world.pump_until(2000, |t| t.snap.action_pending);
    check_member_boot(&tick.snap);
    assert_eq!(world.ups_seen, ups_at_boot, "no join traffic after boot");
    assert_eq!(tick.snap.zt_sends, 0, "a member boot never discovers");
    assert_eq!(tick.member.member_cert, member_before, "RLS1 intact");
    assert_eq!(tick.member.dams_digest, dams_before, "DAMS intact");
    assert_eq!(tick.snap.store_site, testkit::SITE);
    assert_eq!(tick.snap.store_gen, 1);
    let _ = std::fs::remove_file(&flash_path);
}
