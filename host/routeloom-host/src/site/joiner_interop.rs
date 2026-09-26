//! Live E2E (design P3-4 §10.2, P5 §10.4, P6 §11.4): the portable C++
//! member components (`tests/cpp/joiner_interop_peer.cpp`, real Joiner +
//! AuthorityClient + GroupKeyState + MembershipLifecycle on fake
//! radio/flash, real Proxy + Gateway per site) against two real Rust
//! Site Authorities (`SiteService` on SQLite, API1 socket, KGuardMock).
//!
//! This is the process-interop complement of `site::e2e`, which drives the
//! same authority with a Rust `SimDevice`: here the EDHOC Initiator, the
//! scan/candidate FSM, the RLS1 commit + readback, the MemberReady
//! action, the RLRES1 handshake, the GK stage/activate FSM and the
//! RRS1/notice/cutover lifecycle are all the portable C++
//! implementation, while decisions, the durable ledger and the
//! MemberCert/SitePackage/DAMS come from the production Rust code. The
//! authority carriers cross the pipe behind the real USB HostOps
//! fragment layer (`UsbAuthorityAdapter` 0x64/0x65 on this side).
//! The firmware Owner, MeshNode routing, gossip peers and real radio are
//! out of scope: RRS1 normally arrives over the authority channel (see
//! `docs/design/sdk-v1/live-e2e-harness.md`).
//!
//! The peer path comes from `ROUTELOOM_OWNER_PEER` (fallback
//! `ROUTELOOM_JOINER_PEER`) or the CMake build next to this workspace.
//! With no peer configured or built, every test below skips
//! (ignore-equivalent, never a failure), so a bare
//! `cargo test --workspace` stays green; the CI joiner-interop job
//! builds the peer first and always runs them live. An explicit but
//! bogus env path still fails loudly at spawn (a config error, not an
//! absent peer).
//!
//! Time: the test owns one virtual clock (`t0` = real `now_ms` at start,
//! so API1's real-time stamps stay near the authority's virtual stamps).
//! Every step sends `TICK(now)` to the peer, routes the relay ups through
//! `handle_up`, pumps the authority carriers through the USB adapter,
//! runs `tick` on both authorities, forwards the downs and serves KGuard
//! over the sockets — all within the same virtual millisecond, so no
//! decision timeout can fire spuriously.
//!
//! The test adapter rule (§10.2 item 4): only `phase == EdhocMessage (4)`
//! crosses the pipe. Anything else — and any object the shared
//! `routeloom-protocol` codec rejects — fails the test. Abort reasons are
//! mapped by meaning, never cast: the host `AbortReason` and the relay
//! `RelayStatusCode` disagree numerically (host `Timeout = 3` is relay
//! `Busy = 3`, which would lie).
//!
//! Authority carriers (`O` ups, `C` downs, kinds 1..5) cross as whole
//! carriers; this side fragments them through the production USB codec,
//! so the 0x64/0x65 framing, session checks and reassembly limits are
//! the exercised code, not a test double.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use routeloom_client::api1::RouteLoomTransport;
use routeloom_client::site::{Assignment, Decision, KGuardMock, Role, SiteAdmin};
use routeloom_protocol::authority::CarrierKind;
use routeloom_protocol::host_ops::{
    decode_authority_down, encode_authority_up, AuthorityFragment, AUTHORITY_FRAGMENT_DATA_MAX,
    SUB_AUTHORITY_DOWN,
};
use routeloom_protocol::join_relay::{
    RelayBody, RelayDirection, RelayHeader, RelayObject, RelayState, PHASE_EDHOC, RELAY_OBJECT_MAX,
};
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::{test_keypair, FileRootSigner, RootSigner};

use super::group_keys::HostTime;
use super::store::SqliteSiteStore;
use super::testkit;
use super::transport::{DownStatus, InProcessTransport, Outbound, RelayKey, RelayUp};
use super::usb::{authority_sub, UsbAuthorityAdapter};
use super::{ChannelGroupKeyTransport, SiteAuthority, SiteService, SiteSetup};
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

const RPC_MAX: usize = 4096;

struct PeerUp {
    site: u8,
    proxy: u64,
    hops: u8,
    object: Vec<u8>,
}

struct AuthorityUp {
    kind: u8,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct PeerAbort {
    site: u8,
    proxy: u64,
    relay_id: u32,
    gateway_epoch: u32,
    proxy_epoch: u32,
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

/// `G` observation: the owner-leg snapshot (45 B incl. tag).
#[derive(Clone, Debug, Default)]
struct OwnerSnap {
    auth_state: u8,
    join_confirmed: bool,
    gk_current: u32,
    gk_next: u32,
    lifecycle_phase: u8,
    lifecycle_action: u8,
    applied_rs: u32,
    applied_gk: u32,
    holdoff_remaining_ms: u64,
    authority_ready: bool,
    adopted_network: u64,
    own_generation: u32,
    lifecycle_booted: bool,
    enforced_count: u8,
    runtime_flags: u8,
}

struct Tick {
    ups: Vec<PeerUp>,
    aborts: Vec<PeerAbort>,
    authority_ups: Vec<AuthorityUp>,
    snap: Snap,
    member: Member,
    owner: OwnerSnap,
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
    /// Peer binary, if one is available. An explicit env path is always
    /// honoured (a bogus one fails loudly at spawn); otherwise the
    /// default build-tree search applies and `None` means "no peer
    /// here" — the caller skips instead of failing.
    fn peer_path() -> Option<std::path::PathBuf> {
        let explicit = std::env::var_os("ROUTELOOM_OWNER_PEER")
            .or_else(|| std::env::var_os("ROUTELOOM_JOINER_PEER"))
            .map(std::path::PathBuf::from);
        if let Some(path) = explicit {
            return Some(path);
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .parent()?;
        ["build-rf", "build"].into_iter().find_map(|dir| {
            let candidate = root
                .join(dir)
                .join("tests/cpp/routeloom_joiner_interop_peer");
            candidate.is_file().then_some(candidate)
        })
    }

    fn spawn(
        t0: u64,
        seed: u64,
        flash: Option<&std::path::Path>,
        flash_ext: Option<&std::path::Path>,
        verify: bool,
    ) -> Self {
        let path = Self::peer_path()
            .expect("build routeloom_joiner_interop_peer or set ROUTELOOM_OWNER_PEER");
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
        if let Some(file) = flash_ext {
            command.arg("--flash-ext").arg(file);
        }
        if verify {
            command.arg("--verify");
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
            authority_ups: Vec::new(),
            owner: OwnerSnap::default(),
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
                    let gateway_epoch = get_u32(&payload, &mut pos);
                    let proxy_epoch = get_u32(&payload, &mut pos);
                    tick.aborts.push(PeerAbort {
                        site,
                        proxy,
                        relay_id,
                        gateway_epoch,
                        proxy_epoch,
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
                b'O' => {
                    assert!(payload.len() >= 3, "O carries kind + bytes");
                    assert!((1..=5).contains(&payload[1]), "authority kind 1..5");
                    tick.authority_ups.push(AuthorityUp {
                        kind: payload[1],
                        bytes: payload[2..].to_vec(),
                    });
                }
                b'G' => {
                    assert_eq!(payload.len(), 45, "G shape");
                    let mut pos = 1;
                    tick.owner.auth_state = payload[pos];
                    pos += 1;
                    tick.owner.join_confirmed = payload[pos] != 0;
                    pos += 1;
                    tick.owner.gk_current = get_u32(&payload, &mut pos);
                    tick.owner.gk_next = get_u32(&payload, &mut pos);
                    tick.owner.lifecycle_phase = payload[pos];
                    pos += 1;
                    tick.owner.lifecycle_action = payload[pos];
                    pos += 1;
                    tick.owner.applied_rs = get_u32(&payload, &mut pos);
                    tick.owner.applied_gk = get_u32(&payload, &mut pos);
                    tick.owner.holdoff_remaining_ms = get_u64(&payload, &mut pos);
                    tick.owner.authority_ready = payload[pos] != 0;
                    pos += 1;
                    tick.owner.adopted_network = get_u64(&payload, &mut pos);
                    tick.owner.own_generation = get_u32(&payload, &mut pos);
                    tick.owner.lifecycle_booted = payload[pos] != 0;
                    pos += 1;
                    tick.owner.enforced_count = payload[pos];
                    pos += 1;
                    tick.owner.runtime_flags = payload[pos];
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

    fn send_abort(&mut self, site: u8, key: &RelayKey) {
        let mut command = vec![b'B', site];
        command.extend_from_slice(&key.proxy.to_le_bytes());
        command.extend_from_slice(&key.relay_id.to_le_bytes());
        command.extend_from_slice(&key.gateway_epoch.to_le_bytes());
        command.extend_from_slice(&key.proxy_epoch.to_le_bytes());
        self.send(&command);
    }

    fn send_authority_down(&mut self, kind: u8, bytes: &[u8]) {
        assert!((1..=5).contains(&kind), "authority kind 1..5");
        assert!(!bytes.is_empty() && bytes.len() <= 2048, "carrier bound");
        let mut command = vec![b'C', kind];
        command.extend_from_slice(bytes);
        self.send(&command);
    }

    fn request_pull(&mut self, reason: u8) {
        assert!((1..=3).contains(&reason), "pull reason 1..3");
        self.send(&[b'V', reason]);
    }

    /// Powers site proxies off/on between rounds: (site, proxy, muted).
    fn send_mute(&mut self, mutes: &[(u8, u8, bool)]) {
        for (site, proxy, muted) in mutes {
            self.send(&[b'F', *site, *proxy, u8::from(*muted)]);
        }
    }

    /// Injects a gossip-completed RRS1 object (see the `J` tag).
    fn inject_gossip(&mut self, object: &[u8]) {
        assert!(!object.is_empty() && object.len() <= 640, "RRS1 bound");
        let mut command = vec![b'J'];
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

    /// The extended image (RRS slots, then journal slots) for the P6
    /// power-cut handover: 2x640 + 2x1609 bytes.
    fn dump_extended(&mut self) -> Vec<u8> {
        self.send(b"X");
        let mut image = Vec::with_capacity(4498);
        for i in 0..4 {
            let payload = self.recv();
            assert_eq!(payload[0], b'X', "extended slot reply");
            let expect_store = if i < 2 { 2 } else { 3 };
            let expect_len = if i < 2 { 640 } else { 1609 };
            assert_eq!(payload[1], expect_store, "extended store id");
            assert_eq!(payload[2], (i % 2) as u8, "extended slot id");
            assert_eq!(payload.len(), 3 + expect_len, "extended slot image");
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
            gateway_epoch: key.gateway_epoch,
            proxy_epoch: key.proxy_epoch,
        },
        body: RelayBody::Message(body),
    }
    .encode()
    .expect("down object encodes")
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
    /// USB authority adapters per site (None until `attach_authority`).
    usb: [Option<Arc<UsbAuthorityAdapter>>; 2],
    transfer: u32,
    rng_state: u64,
    /// Partition switch: false withholds `C` downs (device goes stale).
    authority_downs_on: bool,
    authority_ups_seen: u64,
    authority_downs_sent: u64,
    authority_fragments: u64,
    /// Reassembled downs withheld from the pipe (other devices, or the
    /// pipe device while partitioned): (device, kind, bytes).
    mailbox: Vec<(u64, u8, Vec<u8>)>,
}

impl World {
    /// `None` when no C++ peer is available: the test skips
    /// (ignore-equivalent). A peer proven present here cannot vanish
    /// mid-test, so `swap_peer` below keeps failing loudly.
    fn start(tag: &str, seed: u64) -> Option<Self> {
        if Peer::peer_path().is_none() {
            eprintln!(
                "SKIP site::joiner_interop: no C++ peer \
                 (build routeloom_joiner_interop_peer or set ROUTELOOM_OWNER_PEER)"
            );
            return None;
        }
        let now = now_ms();
        Some(Self {
            peer: Peer::spawn(now, seed, None, None, false),
            sites: [InteropSite::site_a(tag, now), InteropSite::site_b(tag, now)],
            now,
            decisions: Vec::new(),
            allow_forwards: Vec::new(),
            aborts_seen: Vec::new(),
            ups_seen: 0,
            usb: [None, None],
            transfer: 0,
            rng_state: 0x1234_5678_9ABC_DEF0,
            authority_downs_on: true,
            authority_ups_seen: 0,
            authority_downs_sent: 0,
            authority_fragments: 0,
            mailbox: Vec::new(),
        })
    }

    fn swap_peer(&mut self, t0: u64, seed: u64, flash: &std::path::Path, verify: bool) {
        self.swap_peer_ext(t0, seed, flash, None, verify);
    }

    fn swap_peer_ext(
        &mut self,
        t0: u64,
        seed: u64,
        flash: &std::path::Path,
        flash_ext: Option<&std::path::Path>,
        verify: bool,
    ) {
        self.now = t0;
        self.peer = Peer::spawn(t0, seed, Some(flash), flash_ext, verify);
        // A reboot starts a new boot: the m4s after it answer a
        // re-proof, never the pre-cycle KGuard decision.
        self.decisions.clear();
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
                gateway_epoch: object.header.gateway_epoch,
                proxy_epoch: object.header.proxy_epoch,
                joiner_mac: object.header.joiner_mac,
            },
            hops: up.hops,
            phase: object.header.phase,
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
                        // A reissue-allow m4 carries no KGuard decision at
                        // all (04 §8.5), so a live member row takes the
                        // strict path too.
                        if allowed_here || row.as_ref().is_some_and(|r| r.member) {
                            let row = row.expect("allow committed before its m4");
                            assert!(row.member, "allow row is a member");
                            assert_ne!(row.dams, [0; 32], "DAMS stored with the delivery");
                            let delivered = row
                                .delivered_ms
                                .expect("delivered_ms stored with the delivery");
                            let durable = durable.expect("allow persisted before its m4");
                            assert_eq!(durable.delivered_ms, Some(delivered));
                            assert_eq!(durable.dams, row.dams);
                            // delivered_ms is stamped on the caller's axis:
                            // wall on the API socket path, virtual on the
                            // direct reissue path. Both axes are monotone,
                            // so the commit precedes the send on either.
                            let forwarded_at = now_ms().max(self.now);
                            assert!(
                                delivered <= forwarded_at,
                                "durable approval precedes the m4 send"
                            );
                            self.allow_forwards.push((site, forwarded_at, delivered));
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
                Outbound::Abort { key, reason: _ } => {
                    self.peer.send_abort(site, &key);
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

    /// Attaches the production authority lane (USB adapter + GK
    /// transport, which also arms the P6 channel port) to one site.
    fn attach_authority(&mut self, site_idx: usize) {
        assert!(site_idx < 2, "known site");
        assert!(self.usb[site_idx].is_none(), "attached once");
        let gateway = self.sites[site_idx].gateway;
        let usb = UsbAuthorityAdapter::new(gateway, 7 + site_idx as u64);
        self.sites[site_idx]
            .service
            .set_group_key_transport(ChannelGroupKeyTransport::new(&self.sites[site_idx].service));
        self.sites[site_idx]
            .service
            .set_authority_transport(Some(usb.clone()));
        self.usb[site_idx] = Some(usb);
    }

    /// Which site the pipe device belongs to (its member row decides).
    fn owner_site(&self) -> usize {
        for index in 0..2 {
            if self.member_row(index).is_some() {
                return index;
            }
        }
        0
    }

    /// Routes one `O` up: fragments it like a gateway (real 0x64 codec),
    /// feeds the USB adapter, and pumps completed assemblies into the
    /// authority. Deterministic RNG: the handshake draws from `rng_state`.
    fn route_authority_up(&mut self, up: &AuthorityUp) {
        let kind = CarrierKind::try_from_byte(up.kind).expect("authority kind 1..5");
        assert!((1..=2048).contains(&up.bytes.len()), "carrier bound");
        self.authority_ups_seen += 1;
        let site_idx = self.owner_site();
        self.pump_up_fragments(site_idx, DEVICE_NODE, kind, &up.bytes);
    }

    /// The same gateway-fragment pump for a Rust `FakeDevice` (the
    /// second member in exclusion tests): identical USB framing.
    fn fake_send_up(&mut self, site_idx: usize, device: u64, kind: CarrierKind, bytes: &[u8]) {
        assert!((1..=2048).contains(&bytes.len()), "carrier bound");
        self.pump_up_fragments(site_idx, device, kind, bytes);
    }

    fn pump_up_fragments(&mut self, site_idx: usize, device: u64, kind: CarrierKind, bytes: &[u8]) {
        let usb = self.usb[site_idx]
            .as_ref()
            .expect("attach_authority before the owner leg runs")
            .clone();
        let total = bytes.len();
        self.transfer = self.transfer.wrapping_add(1);
        if self.transfer == 0 {
            self.transfer = 1;
        }
        let transfer = self.transfer;
        let mut offset = 0;
        while offset < total {
            let end = (offset + AUTHORITY_FRAGMENT_DATA_MAX).min(total);
            let body = encode_authority_up(&AuthorityFragment {
                device,
                transfer_id: transfer,
                kind,
                hops: 1,
                total: total as u16,
                offset: offset as u16,
                data: bytes[offset..end].to_vec(),
            })
            .expect("up fragment encodes");
            self.authority_fragments += 1;
            for completed in usb.handle_up(&body, self.now).expect("up assembles") {
                assert_eq!(completed.device, device, "fragment device agrees");
                let mut state = self.rng_state;
                let mut rng = |out: &mut [u8]| {
                    for b in out.iter_mut() {
                        state = state
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        *b = (state >> 33) as u8;
                    }
                    true
                };
                self.sites[site_idx].service.handle_authority_up(
                    completed.device,
                    completed.kind,
                    &completed.bytes,
                    HostTime::sync(self.now),
                    &mut rng,
                );
                self.rng_state = state;
            }
            offset = end;
        }
    }

    /// Drains the USB down queues, reassembles the 0x65 fragments like a
    /// gateway, and forwards the pipe device's carriers as `C` downs.
    /// Anything not forwarded — another device's carriers, or the pipe
    /// device's while the partition switch is off — lands in `mailbox`
    /// for the test to inspect, selectively forward, or drop.
    fn drain_authority_downs(&mut self, site_idx: usize) {
        let usb = match self.usb[site_idx].as_ref() {
            Some(usb) => usb.clone(),
            None => return,
        };
        let mut partial: std::collections::HashMap<(u64, u32), (CarrierKind, Vec<u8>, usize)> =
            std::collections::HashMap::new();
        let mut whole = Vec::new();
        // The adapter stamps admissions with the process monotonic clock;
        // this harness advances its authority's virtual clock separately.
        for down in usb.take_ready(crate::mono_ms()) {
            if authority_sub(&down.bytes) != Some(SUB_AUTHORITY_DOWN) {
                continue;
            }
            self.authority_fragments += 1;
            let fragment = decode_authority_down(&down.bytes).expect("down fragment decodes");
            let entry = partial
                .entry((fragment.device, fragment.transfer_id))
                .or_insert_with(|| (fragment.kind, vec![0; fragment.total as usize], 0));
            assert_eq!(entry.0, fragment.kind, "fragment kind stable");
            let start = fragment.offset as usize;
            entry.1[start..start + fragment.data.len()].copy_from_slice(&fragment.data);
            entry.2 += fragment.data.len();
            if entry.2 == fragment.total as usize {
                let ((device, _), (kind, bytes, _)) = partial
                    .remove_entry(&(fragment.device, fragment.transfer_id))
                    .expect("assembly present");
                whole.push((device, kind as u8, bytes));
            }
        }
        for (device, kind, bytes) in whole {
            if device == DEVICE_NODE && self.authority_downs_on {
                self.peer.send_authority_down(kind, &bytes);
                self.authority_downs_sent += 1;
            } else {
                self.mailbox.push((device, kind, bytes));
            }
        }
    }

    /// Takes the mailboxed carriers for one device (see above).
    fn take_mail(&mut self, device: u64) -> Vec<(u8, Vec<u8>)> {
        let mut kept = Vec::new();
        let mut out = Vec::new();
        for (node, kind, bytes) in self.mailbox.drain(..) {
            if node == device {
                out.push((kind, bytes));
            } else {
                kept.push((node, kind, bytes));
            }
        }
        self.mailbox = kept;
        out
    }

    /// Forwards mailboxed pipe-device carriers selectively (the
    /// SelfRevoked test withholds the notice while delivering the RRS).
    fn forward_mail(&mut self, mut select: impl FnMut(u8, &[u8]) -> bool) {
        let mut kept = Vec::new();
        for (node, kind, bytes) in self.mailbox.drain(..) {
            if node == DEVICE_NODE && select(kind, &bytes) {
                self.peer.send_authority_down(kind, &bytes);
                self.authority_downs_sent += 1;
            } else {
                kept.push((node, kind, bytes));
            }
        }
        self.mailbox = kept;
    }

    /// One virtual step: peer pump, up routing, authority ticks, KGuard.
    fn step(&mut self, dt_ms: u64) -> Tick {
        self.now += dt_ms;
        let tick = self.peer.tick(self.now);
        self.ups_seen += tick.ups.len() as u64;
        for up in &tick.ups {
            self.route_up(up);
        }
        let authority_live = self.usb.iter().any(|slot| slot.is_some());
        if authority_live {
            for up in &tick.authority_ups {
                self.route_authority_up(up);
            }
        }
        for index in 0..2 {
            self.sites[index]
                .service
                .tick(super::group_keys::HostTime::sync(self.now));
            self.drain(index);
        }
        if authority_live {
            for index in 0..2 {
                self.drain_authority_downs(index);
            }
        }
        self.serve_kguard();
        for abort in &tick.aborts {
            self.aborts_seen.push(PeerAbort {
                site: abort.site,
                proxy: abort.proxy,
                relay_id: abort.relay_id,
                gateway_epoch: abort.gateway_epoch,
                proxy_epoch: abort.proxy_epoch,
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
const REMOVAL_REQUIRED: u8 = 3;

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
    let Some(mut world) = World::start("allow", 0xA110) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    let tick = world.pump_until(6000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    assert_eq!(tick.snap.store_site, testkit::SITE);
    assert_eq!(tick.snap.store_gen, 1);
    assert_eq!(world.allow_forwards.len(), 1);
    assert_eq!(world.allow_forwards[0].0, 0);
    assert!(world.allow_forwards[0].2 <= world.allow_forwards[0].1);
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
    let Some(mut world) = World::start("deny", 0xDE17) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
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
    let Some(mut world) = World::start("pending", 0x9E17) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
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
/// V1-F01 (reboot-to-member half: zero join/discovery traffic; the
/// REACHABLE and zero-authority-query halves need the Owner/radio).
#[test]
fn power_cut_after_commit_boots_as_member() {
    let Some(mut world) = World::start("powercut", 0xC07) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
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

    world.swap_peer(world.now + 1000, 0xC08, &flash_path, false);
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

/// V1-R07 over the pipe: the member is revoked while offline, then
/// power-cycles and re-proves its retained RLS1. The real C++ Joiner in
/// VerifyExistingMembership mode ZTs with LastMembership, the real Rust
/// authority answers Removed with a fresh SAK-signed notice in the m4,
/// and the Joiner lands RemovalRequired without touching flash.
#[test]
fn cpp_joiner_removed_rediscovers_over_the_pipe() {
    use routeloom_client::site::RemovalReason;

    let Some(mut world) = World::start("removed", 0xBE07) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    let tick = world.pump_until(6000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    let before = world.peer.dump_flash();
    let dir = world.sites[0].dir.clone();
    let flash_path = dir.join("flash.bin");
    std::fs::write(&flash_path, &before).unwrap();

    // Revoked while offline: the direct notice has no bearer here (no
    // port attached), so the ZT re-proof must carry the removal.
    world.sites[0]
        .link
        .revoke(DEVICE_NODE, 1, RemovalReason::Removed, "r07-rm")
        .unwrap();
    assert!(
        world.member_row(0).as_ref().is_some_and(|row| !row.member),
        "revoke commits the removal"
    );

    // Power cycle into the verify boot: ZT re-proof, not silent adoption.
    let ups_at_boot = world.ups_seen;
    world.swap_peer(world.now + 1000, 0xBE08, &flash_path, true);
    let tick = world.pump_until(12000, |t| t.snap.action_pending);
    assert!(world.ups_seen > ups_at_boot, "the verify boot ZTs");
    assert_ne!(tick.snap.state, 0, "the FSM left Stopped");
    assert_eq!(
        tick.snap.pending_action, REMOVAL_REQUIRED,
        "the verified notice lands RemovalRequired"
    );
    assert_eq!(tick.snap.terminal_kind, REMOVAL_REQUIRED);
    assert_ne!(tick.snap.terminal_at, 0, "terminal action stamped");
    // Nothing committed: the retained RLS1 is evidence, not membership.
    assert_eq!(tick.snap.store_site, testkit::SITE);
    assert_eq!(tick.snap.store_gen, 1);
    assert_eq!(tick.snap.site_writes, 0, "Removed writes nothing");
    assert_ne!(tick.snap.last_read_at, 0, "the RLS1 was read back");
    let _ = std::fs::remove_file(&flash_path);
}

/// V1-R08 straggler over the pipe: the member hears no PREPARE/COMMIT
/// (offline at cutover), then re-proves over ZT and takes the
/// authenticated reissue on the new epoch — real C++ Joiner, real Rust
/// authority, no KGuard round-trip.
#[test]
fn cpp_joiner_cutover_reissue_over_the_pipe() {
    use super::cutover::CUTOVER_PREPARE_WINDOW_MS;
    use super::group_keys::HostTime;
    use super::revocation::RevocationTransport;
    use super::testkit::{Outcome, SimDevice};
    use routeloom_join::renew::{Head, Phase, Receipt};

    type GrantMail = (u64, u64, Vec<u8>);
    struct Channel {
        outbox: Arc<Mutex<Vec<GrantMail>>>,
    }
    impl RevocationTransport for Channel {
        fn send_rrs(&mut self, _node: u64, _object: &[u8]) -> bool {
            true
        }
        fn send_notice(&mut self, _node: u64, _network: u64, _notice: &[u8]) -> bool {
            true
        }
        fn send_grant(&mut self, node: u64, network: u64, plaintext: &[u8]) -> bool {
            self.outbox
                .lock()
                .unwrap()
                .push((node, network, plaintext.to_vec()));
            true
        }
        fn carries_notice(&self) -> bool {
            true
        }
        fn carries_grant(&self) -> bool {
            true
        }
    }

    let Some(mut world) = World::start("reissue", 0xBE08) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    world.sites[0]
        .kguard
        .assign(testkit::GATEWAY, Assignment::Here(Role::Gateway));
    // The gateway joins on the Rust side first (the pipe is still idle,
    // so its m4 cannot stray into the peer).
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let (mut exchange, outcome, _) = gateway.start(
        &world.sites[0].service,
        &world.sites[0].transport,
        world.now,
    );
    assert!(matches!(outcome, Outcome::Waiting), "{outcome:?}");
    let done = world.sites[0]
        .kguard
        .serve_once(&world.sites[0].link)
        .unwrap();
    assert_eq!(done.len(), 1);
    let outcome = gateway.finish(&mut exchange, &world.sites[0].transport);
    assert!(
        matches!(
            outcome,
            Outcome::Result(routeloom_join::JoinResult::Allow { .. })
        ),
        "{outcome:?}"
    );
    // The pipe device joins; the gateway idles as a member.
    let tick = world.pump_until(6000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    let before = world.peer.dump_flash();
    let dir = world.sites[0].dir.clone();
    let flash_path = dir.join("flash.bin");
    std::fs::write(&flash_path, &before).unwrap();

    // Cutover with a captured grant lane; only the gateway ACKs, the
    // pipe device hears nothing and becomes the straggler.
    let grants: Arc<Mutex<Vec<GrantMail>>> = Arc::new(Mutex::new(Vec::new()));
    world.sites[0].service.with(|a| {
        a.set_rrs_transport(Some(Box::new(Channel {
            outbox: grants.clone(),
        })))
    });
    let site_ca = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    let next_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: testkit::SITE_CA,
            subject: testkit::SITE,
            pubkey: test_keypair(0x62).1,
            network_low32: testkit::NETWORK_LOW,
            site_epoch: testkit::SITE_EPOCH + 1,
            usage: 1,
            serial: 8,
            ..CertClaims::default()
        },
        &site_ca,
    )
    .unwrap();
    let outcome = world.sites[0]
        .link
        .cutover(
            testkit::SITE_EPOCH,
            &crate::receive_log::hex_lower(&next_cert),
            "r08-cut-1",
        )
        .unwrap();
    assert_eq!(outcome.state, "preparing");
    let t0 = world.now;
    world.sites[0]
        .service
        .with(|a| a.tick(HostTime::sync(t0 + 1000)));
    world.sites[0]
        .service
        .with(|a| a.tick(HostTime::sync(t0 + 1100)));
    assert_eq!(grants.lock().unwrap().len(), 2);
    let op = super::records::parse_op_token(&outcome.operation_id).unwrap();
    let (gk_epoch, old_network, new_network) = world.sites[0]
        .service
        .with(|a| {
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.old_network, state.new_network)
        })
        .0;
    for (node, _, bytes) in grants.lock().unwrap().clone() {
        if node == DEVICE_NODE {
            continue;
        }
        let receipt = Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network,
            },
            new_network,
            gk_epoch,
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        }
        .encode()
        .unwrap()
        .to_vec();
        let (moved, _) = world.sites[0]
            .service
            .with(|a| a.handle_grant_receipt(node, 1, old_network, &receipt, t0 + 2000));
        assert!(moved);
    }
    let lapse = t0 + 1000 + CUTOVER_PREPARE_WINDOW_MS;
    world.sites[0]
        .service
        .with(|a| a.tick(HostTime::sync(lapse)));
    let progress = world.sites[0]
        .link
        .cutover_operation(&outcome.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(progress.phase, "committed");

    // The straggler re-proves on its old RLS1: an authenticated reissue
    // on the new epoch, with no join.request for KGuard.
    let ups_at_boot = world.ups_seen;
    world.swap_peer(lapse + 1000, 0xBE09, &flash_path, true);
    let decisions_before = world.decisions.len();
    let tick = world.pump_until(12000, |t| t.snap.action_pending);
    assert!(world.ups_seen > ups_at_boot, "the verify boot ZTs");
    check_terminal(&tick.snap, MEMBER_READY);
    assert_eq!(
        world.decisions.len(),
        decisions_before,
        "no KGuard round-trip"
    );
    let row = world.member_row(0).expect("member row on the new epoch");
    assert!(row.member);
    assert_eq!(row.generation, 1);
    assert_eq!(
        world.sites[0].service.with(|a| a.network()).0,
        new_network,
        "authority sits on the new epoch"
    );
    assert_eq!(tick.member.site_cert, next_cert, "new-epoch SiteCert");
    assert_eq!(
        tick.member.member_cert, row.member_cert,
        "reissued MemberCert"
    );
    let _ = std::fs::remove_file(&flash_path);
}

// --- Live owner E2E (P5 §10.4, P6 §11.4) ----------------------------------------
// The tests below run the real C++ owner leg (AuthorityClient +
// GroupKeyState + MembershipLifecycle) against the real Rust authority
// over the USB-framed pipe. Seeds are fixed, every pump is budgeted,
// and the virtual clock never touches the wall clock except for `t0`.

/// C++ `AuthoritySnapshot::State` (sdkv1_authority.hpp).
const AUTH_READY: u8 = 2;

/// C++ `LifecyclePhase` (sdkv1_revocation.hpp).
const PHASE_ACTIVE: u8 = 1;
const PHASE_SELF_REVOKED: u8 = 3;
const PHASE_REMOVING: u8 = 7;
const PHASE_HOLDOFF: u8 = 8;
const PHASE_UNASSIGNED_READY: u8 = 9;
const PHASE_PREPARED: u8 = 10;

/// C++ `LifecycleActionTag` (sdkv1_revocation.hpp). Self-revocation
/// raises `RecoveryRequired` (4); `StartRecoveryJoin` (1) is the tag
/// the firmware Owner acts on, never emitted by the lifecycle itself.
const ACTION_RECOVERY_REQUIRED: u8 = 4;
const ACTION_RESTART_UNASSIGNED: u8 = 2;
const ACTION_ADOPT_NETWORK: u8 = 3;
const RUNTIME_REMOVED: u8 = 1;
const TRUST_ERASED: u8 = 2;
const NETWORK_RETIRED: u8 = 4;
const TRUST_INSTALLED: u8 = 8;

/// Joins the pipe device on site A and attaches the authority lane.
/// Returns the MemberReady tick.
fn join_and_attach(world: &mut World) -> Tick {
    world.sites[0]
        .kguard
        .assign(DEVICE_NODE, Assignment::Here(Role::Endpoint));
    world.attach_authority(0);
    let tick = world.pump_until(6000, |t| t.snap.action_pending);
    check_terminal(&tick.snap, MEMBER_READY);
    world.check_member_material(0, &tick.member);
    tick
}

/// P5 live: join → RLRES1 → JoinConfirm → first-contact GK, with the
/// real C++ channel against the real Rust authority over USB framing.
#[test]
fn live_owner_confirm_and_first_contact_key() {
    let Some(mut world) = World::start("owner-confirm", 0x0E01) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    let tick = join_and_attach(&mut world);
    assert_eq!(tick.snap.store_site, testkit::SITE);

    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    let tick = world.pump_until(8000, |t| {
        t.owner.join_confirmed
            && t.owner.gk_current == active
            && t.owner.authority_ready
            && t.owner.lifecycle_phase == PHASE_ACTIVE
    });
    assert_eq!(tick.owner.auth_state, AUTH_READY);
    assert!(tick.owner.lifecycle_booted, "lifecycle adopted the site");
    let row = world.member_row(0).expect("member row");
    assert!(row.confirmed, "Rust recorded the JoinConfirm");
    assert!(
        world.authority_fragments > 0,
        "USB 0x64/0x65 framing crossed the pipe"
    );
    assert!(
        world.authority_ups_seen > 0 && world.authority_downs_sent > 0,
        "carriers flowed both ways"
    );
    let channels = world.sites[0]
        .service
        .with(|a| a.channels.lock().unwrap().stats().channels)
        .0;
    assert_eq!(channels, 1, "one live channel");
}

/// Pumps until the pipe device confirms and converges on `active`.
fn wait_owner_ready(world: &mut World, active: u32) -> Tick {
    world.pump_until(8000, |t| {
        t.owner.join_confirmed
            && t.owner.gk_current == active
            && t.owner.authority_ready
            && t.owner.lifecycle_phase == PHASE_ACTIVE
    })
}

/// P5 live: a manual rotation stages and activates a fresh GK on the
/// real C++ GK FSM (durable stage ACK → Activate → active ACK).
#[test]
fn live_owner_rotation_update_activate() {
    let Some(mut world) = World::start("owner-rotate", 0x0E02) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    wait_owner_ready(&mut world, active);

    let outcome = world.sites[0]
        .link
        .rotate_group_key(active, "owner-rot-1")
        .unwrap();
    assert_eq!(outcome.from_epoch, active);
    let next = outcome.to_epoch;
    assert_eq!(next, active + 1);

    let tick = world.pump_until(8000, |t| {
        t.owner.gk_current == next && t.owner.lifecycle_phase == PHASE_ACTIVE
    });
    assert!(tick.owner.join_confirmed);
    let status = world.sites[0].link.group_key_status().unwrap();
    assert_eq!(status.active, next, "rotation converged on {next}");
    assert_eq!(status.staged, None);
    assert_eq!(status.unknown, 0, "the member applied with evidence");
    let last = status.last_rotation.expect("converged rotation recorded");
    assert_eq!((last.from_epoch, last.to_epoch), (active, next));
}

/// Rotates when the lane is free, pumping through the 60 s
/// post-activation cleanup window (retryable BUSY) on a budget.
fn rotate_when_ready(world: &mut World, expected: u32, key: &str) -> u32 {
    let mut last_err = String::new();
    for _ in 0..8000 {
        match world.sites[0].link.rotate_group_key(expected, key) {
            Ok(outcome) => {
                assert_eq!(outcome.from_epoch, expected);
                return outcome.to_epoch;
            }
            Err(e) => {
                last_err = format!("{e:?}");
                world.step(25);
            }
        }
    }
    let status = world.sites[0].link.group_key_status().unwrap();
    panic!("rotation stayed BUSY past its budget: {last_err} status={status:?}");
}

/// Direct rotation on the virtual clock: the API1 path stamps the
/// wall clock, which cannot cross a 60 s virtual cleanup window, so
/// back-to-back rotations in one test drive `rotate` with the test's
/// own `HostTime`. Returns the staged `to` epoch.
fn rotate_direct_when_ready(world: &mut World, expected: u32, key: &str) -> u32 {
    for _ in 0..8000 {
        let now = world.now;
        let attempt = world.sites[0]
            .service
            .with(|a| {
                a.rotate(
                    501,
                    super::RotateRequest {
                        expected_active_epoch: expected,
                        key: key.into(),
                    },
                    HostTime::sync(now),
                )
            })
            .0;
        match attempt {
            Ok(result) => {
                let tag = "\"to\":";
                let start = result.find(tag).expect("to epoch") + tag.len();
                let digits = result[start..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>();
                let to: u32 = digits.parse().expect("to epoch number");
                assert_eq!(to, expected + 1);
                return to;
            }
            Err(_) => {
                world.step(25);
            }
        }
    }
    panic!("direct rotation stayed BUSY past its budget");
}

/// P5 live: the device goes stale across two rotations behind a
/// partition, then a single pull recovers it straight to the newest
/// active GK (no history replay).
#[test]
fn live_owner_pull_recovers_stale_key() {
    let Some(mut world) = World::start("owner-pull", 0x0E03) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    wait_owner_ready(&mut world, active);

    // Partition: the host rotates twice (each past its 60 s staging
    // deadline) while the device hears nothing.
    world.authority_downs_on = false;
    for (i, from) in [active, active + 1].into_iter().enumerate() {
        // First via the API socket (production path), then direct on
        // the virtual clock (the API stamps the wall clock, which
        // cannot cross the virtual cleanup window).
        let to = if i == 0 {
            rotate_when_ready(&mut world, from, "owner-stale-0")
        } else {
            rotate_direct_when_ready(&mut world, from, "owner-stale-1")
        };
        assert_eq!(to, from + 1);
        for _ in 0..4000 {
            let now_active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
            if now_active == from + 1 {
                break;
            }
            world.step(25);
        }
        assert_eq!(
            world.sites[0].service.with(|a| a.gks.active_epoch()).0,
            from + 1,
            "rotation {i} activated past its deadline"
        );
    }
    let latest = active + 2;
    assert_eq!(
        world.sites[0].service.with(|a| a.gks.active_epoch()).0,
        latest
    );
    // The device is still on the old key; its channel never noticed.
    world.pump_until(200, |t| t.owner.gk_current == active);
    world.mailbox.clear();

    // Heal and pull: one Update → Activate jumps straight to latest.
    world.authority_downs_on = true;
    world.peer.request_pull(3);
    let tick = world.pump_until(8000, |t| {
        t.owner.gk_current == latest && t.owner.lifecycle_phase == PHASE_ACTIVE
    });
    assert!(tick.owner.authority_ready);
    let status = world.sites[0].link.group_key_status().unwrap();
    assert_eq!(status.active, latest);
    assert_eq!(status.unknown, 0, "the stale member caught up");
}

const NODE_B: u64 = 0x00A1_0000_0000_0201;

/// Joins a Rust-side second member on site 0. Returns its DAMS.
fn join_sim_member(world: &mut World, node: u64, seed: u8) -> [u8; 32] {
    use super::testkit::{Outcome, SimDevice};
    world.sites[0]
        .kguard
        .assign(node, Assignment::Here(Role::Endpoint));
    let mut sim = SimDevice::new(node, seed);
    let (mut exchange, outcome, _) = sim.start(
        &world.sites[0].service,
        &world.sites[0].transport,
        world.now,
    );
    assert!(matches!(outcome, Outcome::Waiting), "{outcome:?}");
    // Serve only this member's request (the pipe device is already a
    // member by the time these tests run, so no other request exists).
    let done = world.sites[0]
        .kguard
        .serve_once(&world.sites[0].link)
        .unwrap();
    assert_eq!(done.len(), 1);
    let outcome = sim.finish(&mut exchange, &world.sites[0].transport);
    assert!(
        matches!(
            outcome,
            Outcome::Result(routeloom_join::JoinResult::Allow { .. })
        ),
        "{outcome:?}"
    );
    let mut dams = [0u8; 32];
    world.sites[0].service.with(|a| {
        dams = a.devices.get(&node).expect("sim member row").dams;
    });
    dams
}

/// The authority net view for a site-0 member at the current epochs.
fn fake_net(world: &mut World) -> super::testkit::AuthorityNet {
    use routeloom_keysched::rlres1::Epochs;
    let network = world.sites[0].service.with(|a| a.network()).0;
    let (_, rs_epoch, gk_epoch) = world.sites[0].service.authority_epochs();
    super::testkit::AuthorityNet {
        network,
        site: testkit::SITE,
        epochs_i: Epochs {
            site_epoch: (network >> 32) as u32,
            rs_epoch,
            gk_epoch,
        },
        epochs_r: Epochs {
            site_epoch: (network >> 32) as u32,
            rs_epoch,
            gk_epoch,
        },
    }
}

/// Runs a `FakeDevice` handshake + JoinConfirm for `node` through the
/// site-0 USB adapter. Returns the open device.
fn fake_confirm(
    world: &mut World,
    node: u64,
    dams: [u8; 32],
    nonce: [u8; 16],
) -> super::testkit::FakeDevice {
    use routeloom_keysched::authority::{BodyHead, JoinConfirmUp};
    let net = fake_net(world);
    let (r1, mut peer) = super::testkit::FakeDevice::begin(node, dams, 0xBEEF, nonce, net);
    world.fake_send_up(0, node, CarrierKind::R1, &r1);
    let mut r3 = Vec::new();
    for _ in 0..200 {
        world.step(25);
        for (kind, bytes) in world.take_mail(node) {
            assert_eq!(kind, CarrierKind::R2 as u8);
            r3 = peer.on_r2(&bytes);
        }
        if !r3.is_empty() {
            break;
        }
    }
    assert!(!r3.is_empty(), "R2 answers the fake R1");
    world.fake_send_up(0, node, CarrierKind::R3, &r3);
    for _ in 0..10 {
        world.step(25);
    }
    let (row, active_epoch) = world.sites[0]
        .service
        .with(|a| {
            (
                a.devices.get(&node).expect("sim member row").clone(),
                a.gks.active_epoch(),
            )
        })
        .0;
    let body = JoinConfirmUp {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id: 1,
        },
        cert_hash: sha256(&row.member_cert),
        boot: 0xF00DBEEF,
        current: active_epoch,
        next: 0,
    }
    .encode();
    world.fake_send_up(
        0,
        node,
        CarrierKind::Envelope,
        &peer.seal(1, &body.unwrap()),
    );
    for _ in 0..200 {
        world.step(25);
        let mail = world.take_mail(node);
        if !mail.is_empty() {
            for (kind, bytes) in &mail {
                assert_eq!(*kind, CarrierKind::Envelope as u8);
                let _ = peer.open(bytes);
            }
            break;
        }
    }
    peer
}

/// P5 live: a removed member with a live channel receives its notice
/// but never the fresh GK, while the remaining member converges.
#[test]
fn live_owner_rotation_excludes_removed() {
    use routeloom_client::site::RemovalReason;
    let Some(mut world) = World::start("owner-excl", 0x0E04) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    wait_owner_ready(&mut world, active);

    // B joins on the Rust side and confirms over its own channel.
    let dams_b = join_sim_member(&mut world, NODE_B, 0xB1);
    let mut peer_b = fake_confirm(&mut world, NODE_B, dams_b, [0xB1; 16]);
    let row_b = world.sites[0]
        .service
        .with(|a| a.devices.get(&NODE_B).expect("B row").clone())
        .0;
    assert!(row_b.confirmed, "B confirmed over its channel");
    // B applies the current key first (it confirmed at `active`, so it
    // already holds it); drain any leftover mail.
    for _ in 0..50 {
        world.step(25);
    }
    for (_, bytes) in world.take_mail(NODE_B) {
        let _ = peer_b.open(&bytes);
    }

    // Revoke B: the rotation to a fresh GK must exclude it.
    let outcome = world.sites[0]
        .link
        .revoke(
            NODE_B,
            row_b.generation,
            RemovalReason::Removed,
            "owner-excl-1",
        )
        .unwrap();
    assert_eq!(outcome.state, "committed");
    let next = active + 1;
    let tick = world.pump_until(8000, |t| {
        t.owner.gk_current == next && t.owner.lifecycle_phase == PHASE_ACTIVE
    });
    assert!(tick.owner.join_confirmed);

    // B's channel carried its notice (type 6) but no Update/Activate
    // for the fresh epoch: opening everything distinct it received
    // must never yield envelope type 3 or 4. Transport retries reuse
    // the same sealed bytes, so dedupe before opening (the replay
    // window would reject the verbatim second copy, as designed).
    let mut saw_notice = false;
    for _ in 0..200 {
        world.step(25);
    }
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for (kind, bytes) in world.take_mail(NODE_B) {
        assert_eq!(kind, CarrierKind::Envelope as u8);
        if !seen.insert(bytes.clone()) {
            continue;
        }
        let (env_type, _) = peer_b.open(&bytes);
        assert!(
            env_type != 3 && env_type != 4,
            "removed B must not receive GK commands, got type {env_type}"
        );
        saw_notice |= env_type == 6;
    }
    assert!(saw_notice, "B received its removal notice");
    let status = world.sites[0].link.group_key_status().unwrap();
    assert_eq!(status.active, next);
    let progress = world.sites[0]
        .link
        .operation(&outcome.operation_id)
        .unwrap()
        .expect("operation tracked");
    assert_eq!(
        progress.distribution.applied, 1,
        "only the remaining member applied: {progress:?}"
    );
}

/// P6 live: revoking an offline member fans the RRS1 out over the
/// authority channel; the real C++ lifecycle applies it, enforces it,
/// and reports Applied, converging the operation for the online member.
#[test]
fn live_owner_rrs_delivery_and_apply() {
    use routeloom_client::site::RemovalReason;
    let Some(mut world) = World::start("owner-rrs", 0x0E05) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    let before = wait_owner_ready(&mut world, active).owner.enforced_count;
    let floor = world.sites[0].service.authority_epochs().1;

    // B joins but stays offline (no channel): the RRS1 must still reach
    // the pipe device over its own channel.
    let _ = join_sim_member(&mut world, NODE_B, 0xB2);
    let row_b = world.sites[0]
        .service
        .with(|a| a.devices.get(&NODE_B).expect("B row").clone())
        .0;
    let outcome = world.sites[0]
        .link
        .revoke(
            NODE_B,
            row_b.generation,
            RemovalReason::Removed,
            "owner-rrs-1",
        )
        .unwrap();
    assert_eq!(outcome.state, "committed");
    assert_eq!(outcome.rs_epoch, floor + 1);

    // The C++ lifecycle applies the new set and returns to Active.
    let tick = world.pump_until(8000, |t| {
        t.owner.applied_rs == floor + 1 && t.owner.lifecycle_phase == PHASE_ACTIVE
    });
    assert!(tick.owner.join_confirmed, "channel survived the RRS");
    assert!(
        tick.owner.enforced_count > before,
        "RRS reached the runtime enforcement port"
    );
    // The revoke also rotated the GK; the online member converges there too.
    let tick = world.pump_until(8000, |t| {
        t.owner.gk_current == active + 1 && t.owner.lifecycle_phase == PHASE_ACTIVE
    });
    assert_eq!(tick.owner.applied_gk, active + 1);
    let progress = world.sites[0]
        .link
        .operation(&outcome.operation_id)
        .unwrap()
        .expect("operation tracked");
    assert_eq!(
        progress.distribution.applied, 1,
        "the online member applied: {progress:?}"
    );
}

/// P6 live: revoking the online pipe device delivers its RemovalNotice
/// over the channel; the real C++ lifecycle erases the site, runs the
/// 600 s holdoff, and reports for restart — across a power cut that
/// carries the RRS/journal image through files.
#[test]
fn live_owner_removal_notice_erase_holdoff() {
    use routeloom_client::site::RemovalReason;
    let Some(mut world) = World::start("owner-remove", 0x0E06) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    wait_owner_ready(&mut world, active);
    let row = world.member_row(0).expect("member row");

    let outcome = world.sites[0]
        .link
        .revoke(
            DEVICE_NODE,
            row.generation,
            RemovalReason::Removed,
            "owner-remove-1",
        )
        .unwrap();
    assert_eq!(outcome.state, "committed");

    // Notice → Removing: the site trust is erased.
    let tick = world.pump_until(8000, |t| t.owner.lifecycle_phase == PHASE_REMOVING);
    assert!(tick.owner.join_confirmed, "notice arrived over the channel");
    let tick = world.pump_until(8000, |t| t.owner.lifecycle_phase == PHASE_HOLDOFF);
    assert_eq!(tick.snap.store_site, 0, "site trust erased");
    assert_eq!(
        tick.owner.runtime_flags & (RUNTIME_REMOVED | TRUST_ERASED),
        RUNTIME_REMOVED | TRUST_ERASED,
        "runtime and site trust were erased before holdoff"
    );
    assert!(
        tick.owner.holdoff_remaining_ms > 0,
        "holdoff runs after erasure"
    );

    // Power cut mid-holdoff: only the flash files cross into the respawn.
    // The radio stays muted afterwards so the fresh Joiner cannot commit
    // a new site while the lifecycle replays the removal (production
    // gates discovery the same way through the holdoff).
    let dir = world.sites[0].dir.clone();
    let flash_path = dir.join("owner-remove-flash.bin");
    let ext_path = dir.join("owner-remove-flash-ext.bin");
    std::fs::write(&flash_path, world.peer.dump_flash()).unwrap();
    std::fs::write(&ext_path, world.peer.dump_extended()).unwrap();
    world.swap_peer_ext(
        world.now + 1000,
        0xE06E06,
        &flash_path,
        Some(&ext_path),
        false,
    );
    world.peer.send_mute(&[(0, 0, true), (1, 0, true)]);
    let tick = world.pump_until(8000, |t| {
        t.owner.lifecycle_phase == PHASE_HOLDOFF && t.owner.lifecycle_booted
    });
    assert_eq!(tick.snap.store_site, 0, "still erased after the cut");
    assert!(
        tick.owner.holdoff_remaining_ms > 500_000,
        "holdoff re-entered from the journal, remaining={}",
        tick.owner.holdoff_remaining_ms
    );

    // Past the holdoff the device reports for restart; the channel is
    // gone with the site (no member row to handshake against).
    let mut tick = tick;
    for _ in 0..700 {
        if tick.owner.lifecycle_phase == PHASE_UNASSIGNED_READY {
            break;
        }
        tick = world.step(1000);
    }
    assert_eq!(tick.owner.lifecycle_phase, PHASE_UNASSIGNED_READY);
    assert_eq!(
        tick.owner.lifecycle_action, ACTION_RESTART_UNASSIGNED,
        "the owner order after the holdoff"
    );
    let _ = std::fs::remove_file(&flash_path);
    let _ = std::fs::remove_file(&ext_path);
}

/// P6 live (#139): an RRS1 naming the device, heard over gossip
/// ahead of its notice, drives the real C++ lifecycle into SelfRevoked
/// with a recovery order instead of silently stalling or mis-applying.
/// The RRS1 bytes are the genuine authority artifact; only the mesh hop
/// is injected (the harness has no gossip peers).
#[test]
fn live_owner_self_revoked_recovers() {
    use routeloom_client::site::RemovalReason;
    let Some(mut world) = World::start("owner-selfrev", 0x0E07) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    wait_owner_ready(&mut world, active);
    let row = world.member_row(0).expect("member row");

    // Revoke behind the partition so the notice cannot land first, then
    // hand the device its own RRS1 as a gossip object.
    world.authority_downs_on = false;
    let outcome = world.sites[0]
        .link
        .revoke(
            DEVICE_NODE,
            row.generation,
            RemovalReason::Removed,
            "owner-selfrev-1",
        )
        .unwrap();
    assert_eq!(outcome.state, "committed");
    for _ in 0..50 {
        world.step(25);
    }
    let rrs_object = world.sites[0]
        .service
        .with(|a| a.rrs_latest_object.clone())
        .0;
    assert!(!rrs_object.is_empty(), "the revoke minted an RRS1");
    world.peer.inject_gossip(&rrs_object);
    let tick = world.pump_until(8000, |t| {
        t.owner.lifecycle_phase == PHASE_SELF_REVOKED
            && t.owner.lifecycle_action == ACTION_RECOVERY_REQUIRED
    });
    assert_eq!(tick.owner.applied_rs, outcome.rs_epoch);

    // The notice lands next: SelfRevoked yields to Removing, and the
    // site is erased exactly like the direct-notice leg. Retried copies
    // share the sealed bytes; the channel replay window drops them.
    world.forward_mail(|_, _| true);
    world.authority_downs_on = true;
    let tick = world.pump_until(8000, |t| {
        t.owner.lifecycle_phase == PHASE_REMOVING || t.owner.lifecycle_phase == PHASE_HOLDOFF
    });
    assert!(
        tick.owner.lifecycle_phase == PHASE_REMOVING || tick.owner.lifecycle_phase == PHASE_HOLDOFF,
        "removal proceeds after the notice"
    );
}

/// P6 live: a cutover stages the next epoch over the channel; the real
/// C++ lifecycle prepares, commits past the window, adopts the new
/// network with its GK, and re-opens the channel there — all online.
#[test]
fn live_owner_cutover_prepare_commit() {
    use super::cutover::CUTOVER_PREPARE_WINDOW_MS;
    let Some(mut world) = World::start("owner-cut", 0x0E08) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    wait_owner_ready(&mut world, active);

    let site_ca = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    let next_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: testkit::SITE_CA,
            subject: testkit::SITE,
            pubkey: test_keypair(0x62).1,
            network_low32: testkit::NETWORK_LOW,
            site_epoch: testkit::SITE_EPOCH + 1,
            usage: 1,
            serial: 8,
            ..CertClaims::default()
        },
        &site_ca,
    )
    .unwrap();
    // The gateway joins on the Rust side first (cutover commits
    // gateway-first and snapshots its targets at commit; only the
    // gateway's Prepared receipt is faked — the pipe device prepares
    // over its real channel).
    {
        use super::testkit::{Outcome, SimDevice};
        world.sites[0]
            .kguard
            .assign(testkit::GATEWAY, Assignment::Here(Role::Gateway));
        let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
        gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
        let (mut exchange, outcome, _) = gateway.start(
            &world.sites[0].service,
            &world.sites[0].transport,
            world.now,
        );
        assert!(matches!(outcome, Outcome::Waiting));
        let done = world.sites[0]
            .kguard
            .serve_once(&world.sites[0].link)
            .unwrap();
        assert_eq!(done.len(), 1);
        let outcome = gateway.finish(&mut exchange, &world.sites[0].transport);
        assert!(matches!(
            outcome,
            Outcome::Result(routeloom_join::JoinResult::Allow { .. })
        ));
    }

    let outcome = world.sites[0]
        .link
        .cutover(
            testkit::SITE_EPOCH,
            &crate::receive_log::hex_lower(&next_cert),
            "owner-cut-1",
        )
        .unwrap();
    assert_eq!(outcome.state, "preparing");

    // PREPARE lands over the channel; the device stages the epoch.
    let tick = world.pump_until(8000, |t| t.owner.lifecycle_phase == PHASE_PREPARED);
    assert!(tick.owner.join_confirmed);
    let op = super::records::parse_op_token(&outcome.operation_id).unwrap();
    let (next_gk, new_network, old_network) = world.sites[0]
        .service
        .with(|a| {
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.new_network, state.old_network)
        })
        .0;
    // The offline gateway's Prepared receipt: its grant never leaves
    // the distributor (no channel), so the test digests the exact
    // bytes the authority would have sent, like the R08 capture.
    {
        use routeloom_join::renew::{Head, Phase, Receipt};
        let grant = world.sites[0]
            .service
            .with(|a| {
                a.grant_bytes(
                    op,
                    testkit::GATEWAY,
                    super::revocation::OutboundKind::Prepare,
                )
            })
            .0
            .expect("gateway grant staged");
        let receipt = Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network,
            },
            new_network,
            gk_epoch: next_gk,
            rs_epoch: 0,
            digest: sha256(&grant),
            status: 0,
        }
        .encode()
        .unwrap()
        .to_vec();
        let now = world.now;
        let (moved, _) = world.sites[0]
            .service
            .with(|a| a.handle_grant_receipt(testkit::GATEWAY, 1, old_network, &receipt, now));
        assert!(moved, "gateway marked prepared");
    }

    // Past the window the commit lands; the device adopts the new
    // network, its GK, and re-opens the channel there.
    for _ in 0..(CUTOVER_PREPARE_WINDOW_MS / 1000 + 10) {
        world.step(1000);
    }
    let tick = world.pump_until(8000, |t| {
        t.owner.lifecycle_phase == PHASE_ACTIVE
            && t.owner.adopted_network == new_network
            && t.owner.gk_current == next_gk
            && t.owner.authority_ready
    });
    assert_eq!(
        tick.owner.lifecycle_action, ACTION_ADOPT_NETWORK,
        "the adoption order fired"
    );
    assert_eq!(
        tick.owner.runtime_flags & (NETWORK_RETIRED | TRUST_INSTALLED),
        NETWORK_RETIRED | TRUST_INSTALLED,
        "cutover retired the old runtime and installed new trust"
    );
    assert_eq!(tick.member.site_cert, next_cert, "new-epoch SiteCert");
    let row = world.member_row(0).expect("member row on the new epoch");
    assert!(row.member);
    assert_eq!(row.member_cert, tick.member.member_cert);
    assert_eq!(
        world.sites[0].service.with(|a| a.network()).0,
        new_network,
        "authority sits on the new epoch"
    );
    // Past the commit grace the offline gateway parks in recovery
    // while the online member stands applied.
    for _ in 0..(super::cutover::CUTOVER_GRACE_MS / 1000 + 5) {
        world.step(1000);
    }
    let progress = world.sites[0]
        .link
        .cutover_operation(&outcome.operation_id)
        .unwrap()
        .expect("cutover tracked");
    assert_eq!(progress.phase, "recovery_pending");
    assert_eq!(
        progress.applied, 1,
        "the online member applied: {progress:?}"
    );
    assert!(progress.recovery_pending, "gateway straggler parked");
}

/// P5 live: a power cut after GK convergence carries the identity/site
/// image through a file; the respawned peer boots as a member, keeps
/// its GK, and re-opens the channel without rejoining.
#[test]
fn live_owner_power_cut_keeps_group_keys() {
    let Some(mut world) = World::start("owner-pcut", 0x0E09) else {
        return; // no C++ peer: skip (ignore-equivalent)
    };
    join_and_attach(&mut world);
    let active = world.sites[0].service.with(|a| a.gks.active_epoch()).0;
    wait_owner_ready(&mut world, active);

    // Rotate once so the asserted key came over the channel, not the package.
    let outcome = world.sites[0]
        .link
        .rotate_group_key(active, "owner-pcut-1")
        .unwrap();
    wait_owner_ready(&mut world, outcome.to_epoch);

    let dir = world.sites[0].dir.clone();
    let flash_path = dir.join("owner-pcut-flash.bin");
    let ext_path = dir.join("owner-pcut-flash-ext.bin");
    std::fs::write(&flash_path, world.peer.dump_flash()).unwrap();
    std::fs::write(&ext_path, world.peer.dump_extended()).unwrap();
    let ups_before = world.ups_seen;
    world.swap_peer_ext(
        world.now + 1000,
        0xE09E09,
        &flash_path,
        Some(&ext_path),
        false,
    );

    // Member boot: no join traffic, same GK, channel re-opens.
    let tick = world.pump_until(8000, |t| {
        t.owner.join_confirmed && t.owner.gk_current == outcome.to_epoch
    });
    assert_eq!(world.ups_seen, ups_before, "no rejoin after the cut");
    assert_eq!(tick.snap.store_site, testkit::SITE);
    assert_eq!(tick.owner.lifecycle_phase, PHASE_ACTIVE);
    assert!(tick.owner.authority_ready, "channel re-opened");
    let _ = std::fs::remove_file(&flash_path);
    let _ = std::fs::remove_file(&ext_path);
}
