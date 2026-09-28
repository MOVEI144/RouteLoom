//! Multi-node mesh E2E (D04, issue #168): real `EspNowSecurityOwner`
//! peers (`tests/cpp/owner_mesh_peer.cpp`, one process per node: Owner +
//! runtime + MeshNode over the host ESP-IDF stubs, NVS-backed Sdkv1Stores
//! over a fake NVS, the real UsbBridge on the gateway) against one real
//! Rust Site Authority, with the harness switching radio frames between
//! the peers and relaying the gateway's USB bytes to the authority.
//!
//! Phase 0 provisions each persona through the proven single-device pipe
//! (`routeloom_joiner_interop_peer` + the same join/authority drive as
//! `site::joiner_interop`): the C++ Joiner commits the RLI1/RLS1 and the
//! owner leg converges, then the slot images are imported into the mesh
//! peer's fake NVS. Phase 1 boots all mesh peers from those images — a
//! field reboot, not a rejoin — and runs the #168 scenarios over the
//! real radio/authority/USB path: RemovalNotice delivery with on-device
//! erasure evidence, survivor GK staged/active ACKs, gateway
//! PREPARED/COMMIT/APPLIED, USB re-authentication and new-epoch traffic.
//! No ACK is ever mocked: every receipt the tests assert comes out of a
//! peer's Owner, and every decision out of the production authority.
//!
//! Peers come from `ROUTELOOM_MESH_PEER` (new) and `ROUTELOOM_OWNER_PEER`
//! (legacy, Phase 0) or the CMake build tree next to this workspace.
//! With either missing, every test below skips (ignore-equivalent, never
//! a failure); the CI interop job builds both peers and always runs
//! them live. Time is one virtual clock shared by all peers and the
//! authority (`t0` = wall `now_ms` at start).

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use routeloom_client::api1::RouteLoomTransport;
use routeloom_client::site::{Assignment, KGuardMock, Role, SiteAdmin};
use routeloom_protocol::authority::CarrierKind;
use routeloom_protocol::host_ops::{SUB_AUTHORITY_DOWN, SUB_AUTHORITY_UP, SUB_SITE_STATE_SET};
use routeloom_protocol::join_relay::{
    decode_join_relay_result, join_relay_sub, RelayBody, RelayDirection, RelayHeader, RelayObject,
    RelayState, PHASE_EDHOC, RELAY_OBJECT_MAX, SUB_JOIN_RELAY_ABORT, SUB_JOIN_RELAY_RESULT,
    SUB_JOIN_RELAY_UP,
};
use routeloom_protocol::{encode_frame, Frame, FrameKind, StreamDecoder};
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
use routeloom_provision::signer::{test_keypair, RootSigner};

use super::group_keys::HostTime;
use super::store::{MemoryStore, SqliteSiteStore};
use super::testkit;
use super::transport::{DownStatus, InProcessTransport, Outbound, RelayKey, RelayUp};
use super::usb::{
    authority_sub, AbortOutcome, ResultOutcome, UpOutcome, UsbAuthorityAdapter, UsbSiteAdapter,
};
use super::{ChannelGroupKeyTransport, SiteAuthority, SiteService};
use crate::acl::Acl;
use crate::{now_ms, serve_client, DeviceSession, SessionPhase, State};

// --- Personas ----------------------------------------------------------------
// The gateway is the site's configured gateway (testkit::GATEWAY); the two
// members are relay-capable mesh nodes. MACs are locally-administered and
// unique per process (each peer sets its own stub station MAC).

const NODE_A: u64 = 0x00A1_0000_0000_0101;
const NODE_B: u64 = 0x00A1_0000_0000_0102;
/// A node id no peer holds: survivor discovery for it models the
/// ordinary mesh chatter (unanswered DISCOVER rounds) a live radio
/// carries while a straggler re-verifies (04 §3.5 evidence).
const NODE_GHOST: u64 = 0x00A1_0000_0000_0999;
const MAC_GW: [u8; 6] = [0x02, 0, 0, 0, 0xA1, 1];
const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0xA1, 2];
const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0xA1, 3];
const SEED_GW: u8 = 0xA1;
const SEED_A: u8 = 0xA2;
const SEED_B: u8 = 0xA3;
// Requested-role bits (rlcw1 member roles): the gateway asks for all
// three like the bridge firmware, members for endpoint|relay like the
// reference firmware.
const ROLE_GW: u8 = 7;
const ROLE_MEMBER: u8 = 3;
// Gateway USB HelloAck capability: HostOps + join relay v2 + authority
// channel (the bits the mesh harness exercises).
const USB_CAP: u32 = (1 << 2) | (1 << 9) | (1 << 10);
const RPC_MAX: usize = 65535;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
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

fn get_u16(payload: &[u8], pos: &mut usize) -> u16 {
    let value = u16::from_le_bytes([payload[*pos], payload[*pos + 1]]);
    *pos += 2;
    value
}

struct Persona {
    node: u64,
    mac: [u8; 6],
    seed: u8,
    role: u8,
    gateway: bool,
}

fn personas() -> [Persona; 3] {
    [
        Persona {
            node: testkit::GATEWAY,
            mac: MAC_GW,
            seed: SEED_GW,
            role: ROLE_GW,
            gateway: true,
        },
        Persona {
            node: NODE_A,
            mac: MAC_A,
            seed: SEED_A,
            role: ROLE_MEMBER,
            gateway: false,
        },
        Persona {
            node: NODE_B,
            mac: MAC_B,
            seed: SEED_B,
            role: ROLE_MEMBER,
            gateway: false,
        },
    ]
}

// --- Site --------------------------------------------------------------------

struct MeshSite {
    service: Arc<SiteService>,
    transport: Arc<InProcessTransport>,
    link: RouteLoomTransport,
    kguard: KGuardMock,
    dir: std::path::PathBuf,
    listener_stop: Arc<AtomicBool>,
    listener_thread: Option<thread::JoinHandle<()>>,
}

impl Drop for MeshSite {
    fn drop(&mut self) {
        self.stop_listener();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl MeshSite {
    fn open_service(
        dir: &std::path::Path,
        now: u64,
    ) -> (Arc<SiteService>, Arc<InProcessTransport>) {
        let mut setup = testkit::setup();
        setup.channel = 6;
        let store = SqliteSiteStore::open(&dir.join("site.db")).unwrap();
        let authority =
            SiteAuthority::open(&setup, Box::new(testkit::sak()), Box::new(store), now).unwrap();
        let service = Arc::new(SiteService::new(authority));
        let transport = InProcessTransport::new();
        service.set_transport(transport.clone());
        (service, transport)
    }

    fn listen(
        dir: &std::path::Path,
        service: &Arc<SiteService>,
    ) -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
        let uid = std::fs::metadata(dir).unwrap().uid();
        let acl = Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"{:016x}\":[\"MEMBERSHIP_READ\",\"MEMBERSHIP_DECIDE\",\"MEMBERSHIP_ADMIN\"]}}}},\"7\":{{\"networks\":{{\"*\":[\"MEMBERSHIP_READ\"]}}}}}}}}",
            testkit::NETWORK_LOW
        ))
        .unwrap();
        let state = Arc::new(State {
            acl,
            site: Some(Arc::clone(service)),
            ..State::default()
        });
        let socket = dir.join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (outbound_tx, _outbound_rx) = mpsc::sync_channel(64);
        let stop = Arc::new(AtomicBool::new(false));
        let accept_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                if accept_stop.load(Ordering::Acquire) {
                    return;
                }
                let uid = routeloom_peercred::peer_uid(&stream).ok();
                let state = Arc::clone(&state);
                let outbound = outbound_tx.clone();
                thread::spawn(move || {
                    let _ = serve_client(
                        routeloom_peercred::IpcStream::from_unix(stream),
                        state,
                        outbound,
                        0,
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(Mutex::new(DeviceSession::new())),
                        uid.map(routeloom_peercred::Principal::UnixUid),
                    );
                });
            }
        });
        (stop, handle)
    }

    fn stop_listener(&mut self) {
        self.listener_stop.store(true, Ordering::Release);
        if let Some(handle) = self.listener_thread.take() {
            let socket = self.dir.join("api.sock");
            let _ = UnixStream::connect(&socket);
            handle.join().expect("api listener stopped");
            std::fs::remove_file(socket).unwrap();
        }
    }

    fn start(tag: &str, now: u64) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-owner-mesh-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (service, transport) = Self::open_service(&dir, now);
        let (listener_stop, listener_thread) = Self::listen(&dir, &service);
        let socket = dir.join("api.sock");
        let link = RouteLoomTransport::new(&socket, u64::from(testkit::NETWORK_LOW));
        Self {
            service,
            transport,
            link,
            kguard: KGuardMock::default(),
            dir,
            listener_stop,
            listener_thread: Some(listener_thread),
        }
    }

    fn restart(&mut self, now: u64) {
        self.stop_listener();
        let placeholder = Arc::new(SiteService::new(testkit::authority(
            Box::new(MemoryStore::default()),
            now,
        )));
        drop(std::mem::replace(&mut self.service, placeholder));
        let (service, transport) = Self::open_service(&self.dir, now);
        service.set_group_key_transport(ChannelGroupKeyTransport::new(&service));
        let (listener_stop, listener_thread) = Self::listen(&self.dir, &service);
        self.service = service;
        self.transport = transport;
        self.link =
            RouteLoomTransport::new(self.dir.join("api.sock"), u64::from(testkit::NETWORK_LOW));
        self.listener_stop = listener_stop;
        self.listener_thread = Some(listener_thread);
    }
}

// --- Phase 0: provision one persona through the legacy joiner peer ------------
// The legacy peer speaks the joiner_interop pipe (single site 0 here);
// the drive below mirrors that module's World for one persona at a time
// (relay ups/downs, KGuard, the USB-framed authority lane). Each persona
// converges to MemberReady + JoinConfirm + active GK before its slot
// images are dumped for the mesh boot.

const LEGACY_RPC_MAX: usize = 4096;
const MEMBER_READY: u8 = 2;
const AUTH_READY: u8 = 2;
const PHASE_ACTIVE: u8 = 1;

fn legacy_peer_path() -> Option<std::path::PathBuf> {
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

fn mesh_peer_path() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("ROUTELOOM_MESH_PEER").map(std::path::PathBuf::from) {
        return Some(path);
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?;
    ["build-rf", "build"].into_iter().find_map(|dir| {
        let candidate = root.join(dir).join("tests/cpp/routeloom_owner_mesh_peer");
        candidate.is_file().then_some(candidate)
    })
}

fn peers_present() -> bool {
    legacy_peer_path().is_some() && mesh_peer_path().is_some()
}

struct DeviceKeys {
    priv_hex: String,
    pub_hex: String,
    cert_hex: String,
}

fn persona_keys(node: u64, seed: u8) -> DeviceKeys {
    let ca = testkit::device_ca();
    let (secret, pubkey) = test_keypair(seed);
    let cert = cert_issue(
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
        &ca,
    )
    .unwrap();
    DeviceKeys {
        priv_hex: hex(&secret),
        pub_hex: hex(&pubkey),
        cert_hex: hex(&cert),
    }
}

struct LegacyUp {
    proxy: u64,
    hops: u8,
    object: Vec<u8>,
}

struct LegacyAuthorityUp {
    kind: u8,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct LegacySnap {
    state: u8,
    action_pending: bool,
    pending_action: u8,
    store_site: u64,
    last_write_at: u64,
    last_read_at: u64,
    terminal_at: u64,
}

#[derive(Default)]
struct LegacyOwner {
    auth_state: u8,
    join_confirmed: bool,
    gk_current: u32,
    lifecycle_phase: u8,
    authority_ready: bool,
}

struct LegacyTick {
    ups: Vec<LegacyUp>,
    authority_ups: Vec<LegacyAuthorityUp>,
    snap: LegacySnap,
    owner: LegacyOwner,
}

struct LegacyPeer {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

impl Drop for LegacyPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl LegacyPeer {
    fn spawn(persona: &Persona, t0: u64, seed: u64) -> Self {
        let path = legacy_peer_path()
            .expect("build routeloom_joiner_interop_peer or set ROUTELOOM_OWNER_PEER");
        let keys = persona_keys(persona.node, persona.seed);
        let site_ca_pub = test_keypair(0x61).1;
        let mut command = Command::new(&path);
        command
            .arg("--node")
            .arg(format!("{:#x}", persona.node))
            .arg("--mac")
            .arg(hex(&persona.mac))
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
            .arg(format!("{}", persona.role))
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().expect("spawn legacy joiner peer");
        let stdin = child.stdin.take().expect("peer stdin");
        let stdout = child.stdout.take().expect("peer stdout");
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, payload: &[u8]) {
        assert!(
            !payload.is_empty() && payload.len() <= LEGACY_RPC_MAX,
            "rpc bound"
        );
        let head = (payload.len() as u16).to_le_bytes();
        self.stdin.write_all(&head).expect("peer input open");
        self.stdin.write_all(payload).expect("peer input open");
        self.stdin.flush().expect("peer input open");
    }

    fn recv(&mut self) -> Vec<u8> {
        let mut head = [0u8; 2];
        self.stdout.read_exact(&mut head).expect("peer alive");
        let length = usize::from(u16::from_le_bytes(head));
        assert!((1..=LEGACY_RPC_MAX).contains(&length), "rpc bound");
        let mut payload = vec![0u8; length];
        self.stdout.read_exact(&mut payload).expect("peer alive");
        payload
    }

    fn tick(&mut self, now: u64) -> LegacyTick {
        let mut command = vec![b'T'];
        command.extend_from_slice(&now.to_le_bytes());
        self.send(&command);
        let mut tick = LegacyTick {
            ups: Vec::new(),
            authority_ups: Vec::new(),
            snap: LegacySnap::default(),
            owner: LegacyOwner::default(),
        };
        loop {
            let payload = self.recv();
            match payload[0] {
                b'U' => {
                    let mut pos = 1;
                    let site = payload[pos];
                    pos += 1;
                    assert_eq!(site, 0, "single-site provision leg");
                    let proxy = get_u64(&payload, &mut pos);
                    let hops = payload[pos];
                    pos += 1;
                    tick.ups.push(LegacyUp {
                        proxy,
                        hops,
                        object: payload[pos..].to_vec(),
                    });
                }
                b'A' => {}
                b'S' => {
                    assert_eq!(payload.len(), 47, "S shape");
                    let mut pos = 1;
                    tick.snap.state = payload[pos];
                    pos += 1;
                    pos += 1; // action_pending u8
                    tick.snap.action_pending = payload[pos - 1] != 0;
                    tick.snap.pending_action = payload[pos];
                    pos += 1;
                    tick.snap.store_site = get_u64(&payload, &mut pos);
                    let _store_gen = get_u32(&payload, &mut pos);
                    let _site_writes = get_u16(&payload, &mut pos);
                    tick.snap.last_write_at = get_u64(&payload, &mut pos);
                    tick.snap.last_read_at = get_u64(&payload, &mut pos);
                    let _zt_sends = get_u32(&payload, &mut pos);
                    tick.snap.terminal_at = get_u64(&payload, &mut pos);
                }
                b'M' => {}
                b'O' => {
                    assert!(payload.len() >= 3, "O carries kind + bytes");
                    tick.authority_ups.push(LegacyAuthorityUp {
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
                    let _gk_next = get_u32(&payload, &mut pos);
                    tick.owner.lifecycle_phase = payload[pos];
                    pos += 1 + 1 + 4 + 4 + 8;
                    tick.owner.authority_ready = payload[pos] != 0;
                }
                b'D' => break,
                b'E' => panic!(
                    "legacy peer fatal: {}",
                    String::from_utf8_lossy(&payload[1..])
                ),
                tag => panic!("unknown legacy peer tag {tag}"),
            }
        }
        tick
    }

    fn send_down(&mut self, to_proxy: u64, object: &[u8]) {
        assert!(object.len() <= RELAY_OBJECT_MAX, "relay object bound");
        let mut command = vec![b'W', 0];
        command.extend_from_slice(&to_proxy.to_le_bytes());
        command.extend_from_slice(object);
        self.send(&command);
    }

    fn send_authority_down(&mut self, kind: u8, bytes: &[u8]) {
        let mut command = vec![b'C', kind];
        command.extend_from_slice(bytes);
        self.send(&command);
    }

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

/// Phase-0 driver: one shared site, one legacy peer at a time.
struct Provision {
    site: MeshSite,
    usb: Arc<UsbAuthorityAdapter>,
    now: u64,
    transfer: u32,
    rng_state: u64,
}

impl Provision {
    fn start(tag: &str, now: u64) -> Self {
        let site = MeshSite::start(tag, now);
        let usb = UsbAuthorityAdapter::new(testkit::GATEWAY, 7);
        site.service
            .set_group_key_transport(ChannelGroupKeyTransport::new(&site.service));
        site.service.set_authority_transport(Some(usb.clone()));
        Self {
            site,
            usb,
            now,
            transfer: 0,
            rng_state: 0x1234_5678_9ABC_DEF0,
        }
    }

    fn down_object(
        key: &RelayKey,
        phase: u8,
        step: u8,
        status: DownStatus,
        body: Vec<u8>,
    ) -> Vec<u8> {
        RelayObject {
            header: RelayHeader {
                dir: RelayDirection::Down,
                relay_id: key.relay_id,
                proxy: key.proxy,
                joiner_mac: key.joiner_mac,
                phase,
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

    /// Joins one persona and dumps its slot images. Returns the two
    /// image paths (flash, flash-ext) inside the site dir.
    fn provision_persona(
        &mut self,
        persona: &Persona,
        seed: u64,
        role: Role,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        self.site
            .kguard
            .assign(persona.node, Assignment::Here(role));
        let mut peer = LegacyPeer::spawn(persona, self.now, seed);
        // Join to MemberReady.
        let mut tick = self.step_peer(&mut peer, persona.node, 25);
        for _ in 1..6000 {
            if tick.snap.action_pending {
                break;
            }
            tick = self.step_peer(&mut peer, persona.node, 25);
        }
        assert!(
            tick.snap.action_pending,
            "persona {:x} MemberReady state={} pend_act={}",
            persona.node, tick.snap.state, tick.snap.pending_action
        );
        assert_eq!(tick.snap.pending_action, MEMBER_READY);
        assert_eq!(tick.snap.store_site, testkit::SITE);
        // RLS1 commit < readback <= MemberReady (the C++ op-log stamps).
        assert_ne!(tick.snap.state, 0, "the FSM left Stopped");
        assert_ne!(tick.snap.last_write_at, 0, "RLS1 sealed");
        assert!(tick.snap.last_write_at <= tick.snap.last_read_at);
        assert!(tick.snap.last_read_at <= tick.snap.terminal_at);
        // Converge the owner leg (channel + JoinConfirm + first GK).
        let active = self.site.service.with(|a| a.gks.active_epoch()).0;
        let mut tick = self.step_peer(&mut peer, persona.node, 25);
        for _ in 1..8000 {
            if tick.owner.join_confirmed
                && tick.owner.gk_current == active
                && tick.owner.authority_ready
                && tick.owner.lifecycle_phase == PHASE_ACTIVE
            {
                break;
            }
            tick = self.step_peer(&mut peer, persona.node, 25);
        }
        assert!(
            tick.owner.join_confirmed,
            "persona {:x} confirmed",
            persona.node
        );
        assert_eq!(tick.owner.auth_state, AUTH_READY);
        assert_eq!(tick.owner.gk_current, active);
        assert_eq!(tick.owner.lifecycle_phase, PHASE_ACTIVE);
        let flash_path = self
            .site
            .dir
            .join(format!("phase0-{:x}-flash.bin", persona.node));
        let ext_path = self
            .site
            .dir
            .join(format!("phase0-{:x}-flash-ext.bin", persona.node));
        std::fs::write(&flash_path, peer.dump_flash()).unwrap();
        std::fs::write(&ext_path, peer.dump_extended()).unwrap();
        (flash_path, ext_path)
    }

    fn step_peer(&mut self, peer: &mut LegacyPeer, node: u64, dt_ms: u64) -> LegacyTick {
        self.now += dt_ms;
        let tick = peer.tick(self.now);
        for up in &tick.ups {
            self.route_up(peer, node, up);
        }
        for up in &tick.authority_ups {
            self.route_authority_up(node, up);
        }
        self.site.service.tick(HostTime::sync(self.now));
        self.drain(peer);
        self.drain_authority_downs(peer, node);
        let _ = self.site.kguard.serve_once(&self.site.link).unwrap();
        self.drain(peer);
        tick
    }

    fn route_up(&mut self, peer: &mut LegacyPeer, node: u64, up: &LegacyUp) {
        let object = RelayObject::decode(&up.object).expect("relay object decodes");
        object.validate().expect("relay object valid");
        assert_eq!(object.header.phase, PHASE_EDHOC, "EDHOC phase only");
        assert_eq!(object.header.dir, RelayDirection::Up);
        assert_eq!(up.proxy, object.header.proxy, "proxy agrees");
        let RelayBody::Message(body) = object.body.clone() else {
            panic!("an up object carries a message");
        };
        let relay = RelayUp {
            key: RelayKey {
                gateway: testkit::GATEWAY,
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
        let _ = node;
        self.site.service.handle_up(relay, self.now);
        self.drain(peer);
    }

    fn drain(&mut self, peer: &mut LegacyPeer) {
        for outbound in self.site.transport.take() {
            match outbound {
                Outbound::Down(down) => {
                    let bytes =
                        Self::down_object(&down.key, down.phase, down.step, down.status, down.body);
                    peer.send_down(down.key.proxy, &bytes);
                }
                Outbound::Abort { .. } => {}
            }
        }
    }

    fn route_authority_up(&mut self, node: u64, up: &LegacyAuthorityUp) {
        use routeloom_protocol::host_ops::AUTHORITY_FRAGMENT_DATA_MAX;
        use routeloom_protocol::host_ops::{encode_authority_up, AuthorityFragment};
        let kind = CarrierKind::try_from_byte(up.kind).expect("authority kind 1..5");
        assert!((1..=2048).contains(&up.bytes.len()), "carrier bound");
        self.transfer = self.transfer.wrapping_add(1).max(1);
        let transfer = self.transfer;
        let total = up.bytes.len();
        let mut offset = 0;
        while offset < total {
            let end = (offset + AUTHORITY_FRAGMENT_DATA_MAX).min(total);
            let body = encode_authority_up(&AuthorityFragment {
                device: node,
                transfer_id: transfer,
                kind,
                hops: if node == testkit::GATEWAY { 0 } else { 1 },
                total: total as u16,
                offset: offset as u16,
                data: up.bytes[offset..end].to_vec(),
            })
            .expect("up fragment encodes");
            for completed in self.usb.handle_up(&body, self.now).expect("up assembles") {
                assert_eq!(completed.device, node, "fragment device agrees");
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
                self.site.service.handle_authority_up(
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

    fn drain_authority_downs(&mut self, peer: &mut LegacyPeer, node: u64) {
        use routeloom_protocol::host_ops::decode_authority_down;
        let mut partial: std::collections::HashMap<(u64, u32), (CarrierKind, Vec<u8>, usize)> =
            std::collections::HashMap::new();
        for down in self.usb.take_ready(crate::mono_ms()) {
            if authority_sub(&down.bytes) != Some(SUB_AUTHORITY_DOWN) {
                continue;
            }
            let fragment = decode_authority_down(&down.bytes).expect("down fragment decodes");
            let entry = partial
                .entry((fragment.device, fragment.transfer_id))
                .or_insert_with(|| (fragment.kind, vec![0; fragment.total as usize], 0));
            let start = fragment.offset as usize;
            entry.1[start..start + fragment.data.len()].copy_from_slice(&fragment.data);
            entry.2 += fragment.data.len();
            if entry.2 == fragment.total as usize {
                let ((device, _), (kind, bytes, _)) = partial
                    .remove_entry(&(fragment.device, fragment.transfer_id))
                    .expect("assembly present");
                // Only the live persona's carriers cross; earlier
                // personas' peers are gone (their mesh boots recover
                // over their own channels later, like field reboots).
                if device == node {
                    peer.send_authority_down(kind as u8, &bytes);
                }
            }
        }
    }
}

// --- Phase 1: the mesh ----------------------------------------------------------------
// One Owner peer per persona, a radio switch with a fixed audibility
// matrix, and the gateway's USB bytes relayed through the production
// session/framing/authority-fragment code into the Site Authority.

/// `G` snapshot, tag excluded. Field order matches the peer's emit_g.
// The observation surface is wider than the first tests: the revoke /
// GK / cutover scenarios assert the epochs, journal and holdoff fields.
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct MeshSnap {
    mode: u8,
    membership: u8,
    authority_started: bool,
    authority_ready: bool,
    join_confirmed: bool,
    link_sessions: u32,
    end_sessions: u32,
    phase: u8,
    stores_healthy: bool,
    adopted_network: u64,
    own_generation: u32,
    applied_rs: u32,
    applied_gk: u32,
    holdoff_remaining_ms: u64,
    gk_current: u32,
    gk_next: u32,
    has_identity: bool,
    has_site: bool,
    site_generation: u32,
    usb_state: u8,
    channel: u8,
    committed_channel: u8,
    tx_overruns: u32,
    sends: u32,
    journal_kind: u8,
    journal_epoch: u32,
    journal_detail: u32,
    rrs_applied: u32,
    recoveries: u32,
    rx_count: u32,
    rx_src: u64,
    rx: Vec<u8>,
    app_tx: Vec<MeshAppTx>,
    demux_drops: u32,
    link_established: u32,
    link_failed: u32,
    link_last_error: u8,
    link_requests: u32,
    link_send_failures: u32,
    end_established: u32,
    end_failed: u32,
    end_last_error: u8,
    has_discovery: bool,
    discovers_rx: u32,
    offers_tx: u32,
    offers_rx: u32,
    proves_rx: u32,
    auths_completed: u32,
    kind_rejects: u32,
    cookie_rejects: u32,
    auth_tag_rejects: u32,
    send_failures: u32,
    scope_raw_rx: u32,
    scope_hint_mismatch: u32,
    scope_mac_rejected: u32,
    scope_unknown_generation: u32,
    scope_accepted: u32,
    scope_key_unavailable: u32,
    scope_budget_dropped: u32,
    /// First 8 bytes of the RLI1 kid (0 without an identity): the
    /// nonsecret fingerprint a revoke must leave untouched (R2).
    id_fp: u64,
    /// ZT legs (D04 §5.1): joiner state/error plus the member
    /// proxy's discover/offer/relay counters.
    join_state: u8,
    join_error: u8,
    proxy_disc_rx: u32,
    proxy_offers_tx: u32,
    proxy_suppressed: u32,
    proxy_relays_started: u32,
    proxy_relays_completed: u32,
    auth_rx: u64,
    auth_tx: u64,
    strikes: u8,
    j_attempts: u32,
    j_m1: u32,
    j_dropped: u32,
    notice_down_live: bool,
    unknown_peer_rx: u32,
    proxy_frames_rejected: u32,
    proxy_cookie_rejects: u32,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct MeshAppTx {
    seq: u64,
    state: u8,
    reason: String,
}

// C++ `DeliveryState` (types.hpp).
const DELIVERY_DELIVERED: u8 = 7;
// C++ `SessionState` (usb_bridge.hpp): the gateway USB is usable in Active.
const USB_ACTIVE: u8 = 3;
// C++ `CoordinatorMode` (sdkv1_security_coordinator.hpp).
const MODE_MEMBER: u8 = 2;
// C++ `LifecyclePhase` (sdkv1_revocation.hpp).
const PHASE_REMOVING: u8 = 7;
const PHASE_HOLDOFF: u8 = 8;
const PHASE_PREPARED: u8 = 10;

#[allow(clippy::field_reassign_with_default)]
fn parse_mesh_snap(payload: &[u8]) -> MeshSnap {
    let mut pos = 1;
    let mut snap = MeshSnap::default();
    snap.mode = payload[pos];
    pos += 1;
    snap.membership = payload[pos];
    pos += 1;
    snap.authority_started = payload[pos] != 0;
    pos += 1;
    snap.authority_ready = payload[pos] != 0;
    pos += 1;
    snap.join_confirmed = payload[pos] != 0;
    pos += 1;
    snap.link_sessions = get_u32(payload, &mut pos);
    snap.end_sessions = get_u32(payload, &mut pos);
    snap.phase = payload[pos];
    pos += 1;
    snap.stores_healthy = payload[pos] != 0;
    pos += 1;
    snap.adopted_network = get_u64(payload, &mut pos);
    snap.own_generation = get_u32(payload, &mut pos);
    snap.applied_rs = get_u32(payload, &mut pos);
    snap.applied_gk = get_u32(payload, &mut pos);
    snap.holdoff_remaining_ms = get_u64(payload, &mut pos);
    snap.gk_current = get_u32(payload, &mut pos);
    snap.gk_next = get_u32(payload, &mut pos);
    snap.has_identity = payload[pos] != 0;
    pos += 1;
    snap.has_site = payload[pos] != 0;
    pos += 1;
    snap.site_generation = get_u32(payload, &mut pos);
    snap.usb_state = payload[pos];
    pos += 1;
    snap.channel = payload[pos];
    pos += 1;
    snap.committed_channel = payload[pos];
    pos += 1;
    snap.tx_overruns = get_u32(payload, &mut pos);
    snap.sends = get_u32(payload, &mut pos);
    snap.journal_kind = payload[pos];
    pos += 1;
    snap.journal_epoch = get_u32(payload, &mut pos);
    snap.journal_detail = get_u32(payload, &mut pos);
    snap.rrs_applied = get_u32(payload, &mut pos);
    snap.recoveries = get_u32(payload, &mut pos);
    snap.rx_count = get_u32(payload, &mut pos);
    snap.rx_src = get_u64(payload, &mut pos);
    let rx_len = payload[pos] as usize;
    pos += 1;
    snap.rx = payload[pos..pos + rx_len].to_vec();
    pos += rx_len;
    let tx_count = payload[pos] as usize;
    pos += 1;
    for _ in 0..tx_count {
        let seq = get_u64(payload, &mut pos);
        let state = payload[pos];
        pos += 1;
        let reason_len = payload[pos] as usize;
        pos += 1;
        let reason = String::from_utf8_lossy(&payload[pos..pos + reason_len]).into_owned();
        pos += reason_len;
        snap.app_tx.push(MeshAppTx { seq, state, reason });
    }
    snap.demux_drops = get_u32(payload, &mut pos);
    snap.link_established = get_u32(payload, &mut pos);
    snap.link_failed = get_u32(payload, &mut pos);
    snap.link_last_error = payload[pos];
    pos += 1;
    snap.link_requests = get_u32(payload, &mut pos);
    snap.link_send_failures = get_u32(payload, &mut pos);
    snap.end_established = get_u32(payload, &mut pos);
    snap.end_failed = get_u32(payload, &mut pos);
    snap.end_last_error = payload[pos];
    pos += 1;
    snap.has_discovery = payload[pos] != 0;
    pos += 1;
    snap.discovers_rx = get_u32(payload, &mut pos);
    snap.offers_tx = get_u32(payload, &mut pos);
    snap.offers_rx = get_u32(payload, &mut pos);
    snap.proves_rx = get_u32(payload, &mut pos);
    snap.auths_completed = get_u32(payload, &mut pos);
    snap.kind_rejects = get_u32(payload, &mut pos);
    snap.cookie_rejects = get_u32(payload, &mut pos);
    snap.auth_tag_rejects = get_u32(payload, &mut pos);
    snap.send_failures = get_u32(payload, &mut pos);
    snap.scope_raw_rx = get_u32(payload, &mut pos);
    snap.scope_hint_mismatch = get_u32(payload, &mut pos);
    snap.scope_mac_rejected = get_u32(payload, &mut pos);
    snap.scope_unknown_generation = get_u32(payload, &mut pos);
    snap.scope_accepted = get_u32(payload, &mut pos);
    snap.scope_key_unavailable = get_u32(payload, &mut pos);
    snap.scope_budget_dropped = get_u32(payload, &mut pos);
    snap.id_fp = get_u64(payload, &mut pos);
    snap.join_state = payload[pos];
    pos += 1;
    snap.join_error = payload[pos];
    pos += 1;
    snap.proxy_disc_rx = get_u32(payload, &mut pos);
    snap.proxy_offers_tx = get_u32(payload, &mut pos);
    snap.proxy_suppressed = get_u32(payload, &mut pos);
    snap.proxy_relays_started = get_u32(payload, &mut pos);
    snap.proxy_relays_completed = get_u32(payload, &mut pos);
    snap.auth_rx = get_u64(payload, &mut pos);
    snap.auth_tx = get_u64(payload, &mut pos);
    snap.strikes = payload[pos];
    pos += 1;
    snap.j_attempts = get_u32(payload, &mut pos);
    snap.j_m1 = get_u32(payload, &mut pos);
    snap.j_dropped = get_u32(payload, &mut pos);
    snap.notice_down_live = payload[pos] != 0;
    pos += 1;
    snap.unknown_peer_rx = get_u32(payload, &mut pos);
    snap.proxy_frames_rejected = get_u32(payload, &mut pos);
    snap.proxy_cookie_rejects = get_u32(payload, &mut pos);
    assert_eq!(pos, payload.len(), "G fully consumed");
    snap
}

struct MeshTx {
    dst_mac: [u8; 6],
    bytes: Vec<u8>,
}

struct MeshTick {
    tx: Vec<MeshTx>,
    usb: Vec<u8>,
    snap: MeshSnap,
    /// The peer lifecycle-rebooted (exit 42) during this tick and
    /// already runs respawned (the gateway's USB needs a new Hello).
    rebooted: bool,
}

struct MeshPeer {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    node: u64,
    mac: [u8; 6],
    role: u8,
    gateway: bool,
    seed: u64,
    usb_secret_hex: String,
    nvs_save: std::path::PathBuf,
    t0: u64,
    booted: bool,
    /// Clean lifecycle reboots (exit 42) respawned so far.
    reboots: u32,
    switching_cuts: u32,
}

impl Drop for MeshPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl MeshPeer {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        persona: &Persona,
        t0: u64,
        seed: u64,
        flash: &std::path::Path,
        flash_ext: &std::path::Path,
        usb_secret_hex: &str,
        nvs_save: &std::path::Path,
    ) -> Self {
        let mut child = Self::launch(
            persona.node,
            &persona.mac,
            persona.role,
            persona.gateway,
            t0,
            seed,
            usb_secret_hex,
            None,
            Some((flash, flash_ext)),
            nvs_save,
        );
        let stdin = child.stdin.take().expect("peer stdin");
        let stdout = child.stdout.take().expect("peer stdout");
        Self {
            child,
            stdin,
            stdout,
            node: persona.node,
            mac: persona.mac,
            role: persona.role,
            gateway: persona.gateway,
            seed,
            usb_secret_hex: usb_secret_hex.to_string(),
            nvs_save: nvs_save.to_path_buf(),
            t0,
            booted: false,
            reboots: 0,
            switching_cuts: 0,
        }
    }

    /// Launches the peer process: first boot from the Phase-0 flash
    /// images, reboots from the NVS image the exiting peer saved
    /// (flash surviving the reset, RAM lost — like silicon).
    #[allow(clippy::too_many_arguments)]
    fn launch(
        node: u64,
        mac: &[u8; 6],
        role: u8,
        gateway: bool,
        t0: u64,
        seed: u64,
        usb_secret_hex: &str,
        nvs_load: Option<&std::path::Path>,
        flash: Option<(&std::path::Path, &std::path::Path)>,
        nvs_save: &std::path::Path,
    ) -> Child {
        let path =
            mesh_peer_path().expect("build routeloom_owner_mesh_peer or set ROUTELOOM_MESH_PEER");
        let mut command = Command::new(&path);
        command
            .arg("--node")
            .arg(format!("{node:#x}"))
            .arg("--mac")
            .arg(hex(mac))
            .arg("--role")
            .arg(format!("{role}"))
            .arg("--t0")
            .arg(format!("{t0}"))
            .arg("--seed")
            .arg(format!("{seed}"))
            .arg(if gateway { "--gateway" } else { "--member" })
            .arg("--channel")
            .arg("6")
            .arg("--netlow")
            .arg(format!("{:#x}", testkit::NETWORK_LOW))
            .arg("--gw1")
            .arg(format!("{:#x}", testkit::GATEWAY));
        if let Some(nvs) = nvs_load {
            command.arg("--nvs-load").arg(nvs);
        }
        if let Some((flash, flash_ext)) = flash {
            command.arg("--flash").arg(flash);
            command.arg("--flash-ext").arg(flash_ext);
        }
        command.arg("--nvs-save").arg(nvs_save);
        if gateway {
            command.arg("--usb-secret").arg(usb_secret_hex);
            command.arg("--cap").arg(format!("{USB_CAP}"));
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command.spawn().expect("spawn mesh peer")
    }

    /// Respawns after a clean lifecycle reboot (exit 42): the NVS
    /// image the peer saved on the way out becomes the new boot
    /// image, the clock continues at `now`, and the PRNG stream
    /// moves on (a reboot reseeds). Any other exit is a crash.
    fn respawn(&mut self, now: u64) {
        let status = self.child.wait().expect("peer reaped");
        assert!(
            matches!(status.code(), Some(42 | 43)),
            "mesh peer {:x} crashed (not a lifecycle reboot): {status:?}",
            self.node
        );
        if status.code() == Some(43) {
            self.switching_cuts += 1;
        }
        self.reboots += 1;
        self.t0 = now;
        let nvs_save = self.nvs_save.clone();
        let usb_secret_hex = self.usb_secret_hex.clone();
        self.child = Self::launch(
            self.node,
            &self.mac,
            self.role,
            self.gateway,
            now,
            self.seed.wrapping_add(u64::from(self.reboots)),
            &usb_secret_hex,
            Some(&nvs_save),
            None,
            &nvs_save,
        );
        self.stdin = self.child.stdin.take().expect("peer stdin");
        self.stdout = self.child.stdout.take().expect("peer stdout");
    }

    fn send(&mut self, payload: &[u8]) {
        assert!(!payload.is_empty() && payload.len() <= RPC_MAX, "rpc bound");
        let head = (payload.len() as u16).to_le_bytes();
        self.stdin.write_all(&head).expect("peer input open");
        self.stdin.write_all(payload).expect("peer input open");
        self.stdin.flush().expect("peer input open");
    }

    /// Reads one frame; `None` is a clean peer exit (EOF): the
    /// caller reaps it (a lifecycle reboot respawns, anything else
    /// panics). A mid-frame death is always a crash.
    fn recv(&mut self) -> Option<Vec<u8>> {
        let mut head = [0u8; 2];
        let mut at = 0;
        while at < head.len() {
            match self.stdout.read(&mut head[at..]).expect("peer alive") {
                0 if at == 0 => return None,
                0 => panic!("peer {:x} died mid-frame", self.node),
                n => at += n,
            }
        }
        let length = usize::from(u16::from_le_bytes(head));
        assert!((1..=RPC_MAX).contains(&length), "rpc bound");
        let mut payload = vec![0u8; length];
        self.stdout.read_exact(&mut payload).expect("peer alive");
        Some(payload)
    }

    fn tick(&mut self, now: u64) -> MeshTick {
        // A power cut after durable Switching can be followed by the
        // lifecycle's adoption reboot on the first resumed tick.
        // Both boots read saved NVS; a third reboot is a loop.
        for attempt in 0..3 {
            let mut command = vec![b'T'];
            command.extend_from_slice(&now.to_le_bytes());
            self.send(&command);
            if let Some(mut tick) = self.recv_tick() {
                tick.rebooted = attempt > 0;
                return tick;
            }
            self.respawn(now);
        }
        panic!("peer {:x} rebooted three times in one tick", self.node);
    }

    /// Drains one tick's frames; `None` when the peer exited mid-tick
    /// (a lifecycle reboot — the caller respawns and re-drives).
    fn recv_tick(&mut self) -> Option<MeshTick> {
        let mut tick = MeshTick {
            tx: Vec::new(),
            usb: Vec::new(),
            snap: MeshSnap::default(),
            rebooted: false,
        };
        let mut have_snap = false;
        loop {
            let payload = self.recv()?;
            match payload[0] {
                b'X' => {
                    assert!(payload.len() >= 8, "X carries a MAC + frame");
                    let mut dst_mac = [0u8; 6];
                    dst_mac.copy_from_slice(&payload[1..7]);
                    tick.tx.push(MeshTx {
                        dst_mac,
                        bytes: payload[7..].to_vec(),
                    });
                }
                b'B' => tick.usb.extend_from_slice(&payload[1..]),
                b'G' => {
                    tick.snap = parse_mesh_snap(&payload);
                    have_snap = true;
                }
                b'D' => break,
                b'E' => panic!(
                    "mesh peer fatal: {}",
                    String::from_utf8_lossy(&payload[1..])
                ),
                tag => panic!("unknown mesh peer tag {tag}"),
            }
        }
        assert!(have_snap, "every tick ends with a snapshot");
        assert_eq!(
            tick.snap.tx_overruns, 0,
            "radio capture overrun: size the ticks, never drop silently"
        );
        Some(tick)
    }

    fn send_rx(&mut self, src_mac: &[u8; 6], dst_mac: &[u8; 6], frame: &[u8]) {
        let mut command = vec![b'R'];
        command.extend_from_slice(src_mac);
        command.extend_from_slice(dst_mac);
        command.extend_from_slice(frame);
        self.send(&command);
    }

    fn send_usb(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        for chunk in bytes.chunks(RPC_MAX - 1) {
            let mut command = vec![b'U'];
            command.extend_from_slice(chunk);
            self.send(&command);
        }
    }

    fn send_complete(&mut self, results: &[u8]) {
        if results.is_empty() {
            return;
        }
        let mut command = vec![b'K'];
        command.extend_from_slice(results);
        self.send(&command);
    }

    fn app_send(&mut self, dst: u64, payload: &[u8]) {
        assert!((1..=128).contains(&payload.len()), "app payload bound");
        let mut command = vec![b'S'];
        command.extend_from_slice(&dst.to_le_bytes());
        command.extend_from_slice(payload);
        self.send(&command);
    }

    /// C4 fault: a field power cut. The peer process takes the same
    /// exit-42 marker as a lifecycle esp_restart, so the next tick
    /// respawns it from the saved NVS image through the production
    /// boot path — RAM state is genuinely gone.
    fn power_cut(&mut self) {
        self.send(b"P");
    }

    fn cut_after_switching(&mut self) {
        self.send(b"F");
    }
}

/// The switched radio: `audible[from][to]` plus same-channel delivery.
/// Every unicast completion reports whether the switch delivered the
/// frame; broadcasts always succeed (no MAC ACK on broadcast).
///
/// Fault injection (D04 §5.1) is directed and bounded: tests arm a
/// rule at a program point tied to observed host intent (e.g. "COMMIT
/// dispatched to A", read from the production op state) — never by
/// sniffing ciphertext offsets. Every rule carries a counter so the
/// test proves the fault actually hit.
struct Switch {
    audible: [[bool; 3]; 3],
    /// The construction-time matrix: `heal` restores legs from here,
    /// so a forced-multihop world heals back to multi-hop, not to a
    /// direct radio the test never had.
    base: [[bool; 3]; 3],
    delivered: u64,
    dropped: u64,
    /// Drop the next N frames on the directed leg (the sender's
    /// completion reports failure, like lost airtime).
    drop_next: [[u32; 3]; 3],
    /// Deliver the frame but report failure (a lost MAC ACK: the peer
    /// retries while the far side already holds the frame).
    ack_drop_next: [[u32; 3]; 3],
    /// Hold frames on the directed leg this long before delivery.
    delay_ms: [[u64; 3]; 3],
    /// Per-leg evidence: what crossed and what the switch ate.
    leg_delivered: [[u64; 3]; 3],
    leg_dropped: [[u64; 3]; 3],
    /// R1: lose only gateway-origin authority object chunks for A.
    drop_notice_chunks: bool,
    notice_chunks_dropped: u32,
    notice_manifests_delivered: u32,
    c7_capture: bool,
    c7_hold_data: bool,
    c7_old_data: Option<Vec<u8>>,
    c7_old_discover: Option<Vec<u8>>,
    c7_old_resume: Option<(usize, Vec<u8>)>,
    c7_old_cert: Option<Vec<u8>>,
}

impl Switch {
    fn direct() -> Self {
        Self {
            audible: [[true; 3]; 3],
            base: [[true; 3]; 3],
            delivered: 0,
            dropped: 0,
            drop_next: [[0; 3]; 3],
            ack_drop_next: [[0; 3]; 3],
            delay_ms: [[0; 3]; 3],
            leg_delivered: [[0; 3]; 3],
            leg_dropped: [[0; 3]; 3],
            drop_notice_chunks: false,
            notice_chunks_dropped: 0,
            notice_manifests_delivered: 0,
            c7_capture: false,
            c7_hold_data: false,
            c7_old_data: None,
            c7_old_discover: None,
            c7_old_resume: None,
            c7_old_cert: None,
        }
    }

    /// Forced multi-hop: A (1) and the gateway (0) cannot hear each
    /// other in either direction; everything between them relays via B.
    fn forced_multihop() -> Self {
        let mut switch = Self::direct();
        switch.audible[0][1] = false;
        switch.audible[1][0] = false;
        switch.base = switch.audible;
        switch
    }

    /// Directed audibility at runtime (partition/heal). A reconnect
    /// never replays frames dropped while the leg was down.
    fn set_audible(&mut self, from: usize, to: usize, audible: bool) {
        self.audible[from][to] = audible;
    }

    /// Cut one peer off the air both ways (isolation).
    fn isolate(&mut self, peer: usize) {
        for other in 0..3 {
            self.audible[peer][other] = false;
            self.audible[other][peer] = false;
        }
    }

    /// Reopen one peer's legs to the construction-time matrix.
    fn heal(&mut self, peer: usize) {
        for other in 0..3 {
            self.audible[peer][other] = self.base[peer][other];
            self.audible[other][peer] = self.base[other][peer];
        }
    }

    /// Keep actual old-network carriers for C7. A's certificate is in
    /// an EDHOC step 2/3 object; a large object starts in chunk zero.
    fn c7_observe(&mut self, from: usize, dst_mac: [u8; 6], frame: &[u8], b_mac: [u8; 6]) {
        if !self.c7_capture || (from != 1 && from != 0) {
            return;
        }
        if from == 1
            && dst_mac == b_mac
            && frame.len() > 5
            && frame[..4] == *b"RL\x02\0"
            && frame[4] == 16
            && self.c7_old_data.is_none()
        {
            self.c7_old_data = Some(frame.to_vec());
        }
        if frame.len() < 48 || frame[..4] != *b"RLD1" {
            return;
        }
        if from == 1 && dst_mac == BROADCAST_MAC && frame[5] == 1 && self.c7_old_discover.is_none()
        {
            self.c7_old_discover = Some(frame.to_vec());
        }
        if dst_mac != b_mac {
            return;
        }
        let (phase, step) = match frame[5] {
            3 => (frame[45], frame[46]),
            5 if frame.len() > 56 && frame[50..52] == [0, 0] => (frame[55], frame[56]),
            _ => return,
        };
        if phase == 5 && self.c7_old_resume.is_none() {
            self.c7_old_resume = Some((from, frame.to_vec()));
        }
        if from == 1 && phase == 4 && (step == 2 || step == 3) && self.c7_old_cert.is_none() {
            self.c7_old_cert = Some(frame.to_vec());
        }
    }
}

fn notice_object_frame(frame: &[u8], kind: u8) -> bool {
    // The immutable wire header identifies the target and carrier type;
    // the authority envelope and its encrypted chunks remain opaque.
    frame.len() >= 32
        && frame[0..4] == [b'R', b'L', 2, 0]
        && frame[4] == kind
        && frame[16..24] == testkit::GATEWAY.to_be_bytes()
        && frame[24..32] == NODE_A.to_be_bytes()
}

const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// Completed authority carriers per pump: (device, kind, bytes).
type AuthorityUps = Vec<(u64, CarrierKind, Vec<u8>)>;
/// One switched radio delivery: (to_peer, src_mac, dst_mac, frame).
type SwitchDelivery = (usize, [u8; 6], [u8; 6], Vec<u8>);

/// One queued USB frame plus its join-relay 0x63 correlation: the
/// adapter learns the request id only when the frame actually goes on
/// the wire (production `note_sent` discipline — never for a frame
/// still sitting in this queue).
struct PendingFrame {
    frame: Frame,
    join_note: Option<(Arc<UsbSiteAdapter>, RelayKey, bool)>,
}

/// The gateway USB host end: the production session, framing,
/// authority-fragment and join-relay codecs; only the pump below is
/// test code (it mirrors the production `site_once` relay half: 0x60
/// ups decode through the bound [`UsbSiteAdapter`] into the join lane,
/// 0x62/0x63 end attempts, and 0x61/0x62 downs drain with 0x63
/// correlation — the ZT recovery road for revoked and cutover
/// stragglers, D04 §5.1).
#[allow(dead_code)]
struct UsbHost {
    session: DeviceSession,
    decoder: StreamDecoder,
    request: u64,
    pending: Vec<PendingFrame>,
    hello_node: Option<u64>,
    hello_network: Option<u64>,
    hello_capability: Option<u32>,
    auth_sessions: Vec<u64>,
    session_losses: u64,
    ups_seen: u64,
    downs_sent: u64,
    join_ups_seen: u64,
    join_downs_sent: u64,
    other_host_ops: u64,
    data_frames: u64,
    diagnostics: u64,
    /// Sim-time of the last inbound wire bytes — the silent-peer
    /// watchdog clock (mirrors `adapter_writer_loop`'s last_rx).
    last_rx_ms: u64,
    /// Sim-time of the last `begin()` — paces handshake retries.
    last_begin_ms: u64,
    /// Sim-time of the last emitted frame — paces the idle keepalive.
    last_tx_ms: u64,
}

impl UsbHost {
    fn new() -> Self {
        Self {
            session: DeviceSession::new(),
            decoder: StreamDecoder::default(),
            request: 1,
            pending: Vec::new(),
            hello_node: None,
            hello_network: None,
            hello_capability: None,
            auth_sessions: Vec::new(),
            session_losses: 0,
            ups_seen: 0,
            downs_sent: 0,
            join_ups_seen: 0,
            join_downs_sent: 0,
            other_host_ops: 0,
            data_frames: 0,
            diagnostics: 0,
            last_rx_ms: 0,
            last_begin_ms: 0,
            last_tx_ms: 0,
        }
    }

    fn hello_bytes(&mut self, now: u64) -> Vec<u8> {
        self.last_begin_ms = now;
        encode_frame(&self.session.begin()).expect("hello encodes")
    }

    /// Queues one sealed frame; returns its request id for 0x63
    /// correlation (the id is spent even when the frame waits behind
    /// a credit-short head — the device answers the id it sees).
    fn queue_data(&mut self, kind: FrameKind, body: Vec<u8>) -> u64 {
        let request = self.request;
        self.request += 1;
        self.pending.push(PendingFrame {
            frame: Frame {
                kind,
                flags: 0,
                session: 0,
                request,
                body,
            },
            join_note: None,
        });
        request
    }

    fn queue_join_down(
        &mut self,
        join: &Arc<UsbSiteAdapter>,
        key: RelayKey,
        terminal: bool,
        body: Vec<u8>,
    ) {
        let request = self.request;
        self.request += 1;
        self.pending.push(PendingFrame {
            frame: Frame {
                kind: FrameKind::HostOps,
                flags: 0,
                session: 0,
                request,
                body,
            },
            join_note: Some((Arc::clone(join), key, terminal)),
        });
        self.join_downs_sent += 1;
    }

    /// Routes one verified join-relay inner (0x60/0x62/0x63) exactly
    /// like the production site lane: 0x60 ups decode into the join
    /// lane, aborts and failed results end their attempts.
    fn route_join(
        &mut self,
        sub: u8,
        request: u64,
        inner: &[u8],
        now: u64,
        join: &UsbSiteAdapter,
        service: &SiteService,
    ) {
        match sub {
            SUB_JOIN_RELAY_UP => match join.handle_up(inner, now) {
                Ok(UpOutcome::Relay(up)) => {
                    self.join_ups_seen += 1;
                    let _ = service.handle_up_time(up, HostTime::sync(now));
                }
                Ok(UpOutcome::ProxyAbort { key }) => {
                    let _ = service.with(|a| {
                        a.fail_relay(key, "proxy_abort", "proxy aborted".to_string(), now)
                    });
                }
                Ok(UpOutcome::Phase5Refused | UpOutcome::CapacityRefused) | Err(_) => {}
            },
            SUB_JOIN_RELAY_ABORT => {
                if let Ok(AbortOutcome::RelayOver { key, reason }) = join.handle_abort(inner) {
                    let _ = service
                        .with(|a| a.fail_relay(key, "gateway_abort", format!("{reason:?}"), now));
                }
            }
            SUB_JOIN_RELAY_RESULT => {
                if let Ok(ResultOutcome::Failed { key }) = join.handle_result(request, inner) {
                    let result_code = decode_join_relay_result(inner)
                        .map(|result| format!("{:?}", result.result))
                        .unwrap_or_else(|_| "Malformed".to_string());
                    let _ = service.with(|a| a.fail_relay(key, "down_admission", result_code, now));
                }
            }
            _ => {
                self.other_host_ops += 1;
            }
        }
    }

    /// Feeds device bytes, routes verified inners, and returns the bytes
    /// to write back. Authority ups are assembled through `authority`
    /// and completed carriers are returned for the authority; join
    /// relay runs inline through `join` into `service` (both families
    /// share this USB session, like the production lane).
    fn pump(
        &mut self,
        bytes: &[u8],
        now: u64,
        authority: &UsbAuthorityAdapter,
        join: &Arc<UsbSiteAdapter>,
        service: &SiteService,
    ) -> (Vec<u8>, AuthorityUps) {
        let mut out = Vec::new();
        let mut completed = Vec::new();
        if !bytes.is_empty() {
            self.last_rx_ms = now;
        }
        // Silent-peer watchdog + retry pacing, mirroring
        // adapter_writer_loop: an Active session with no inbound
        // traffic for SESSION_LIVENESS_MS is re-handshaken in place —
        // the device's credit stall cannot recover on its own
        // (usb-protocol §4) — and a lost handshake attempt is re-sent
        // on HELLO_RETRY_MS.
        const SESSION_LIVENESS_MS: u64 = 15_000;
        const HELLO_RETRY_MS: u64 = 4_000;
        const KEEPALIVE_INTERVAL_MS: u64 = 5_000;
        let active = self.session.phase == SessionPhase::Active;
        let handshaking = matches!(
            self.session.phase,
            SessionPhase::AwaitHelloAck | SessionPhase::AwaitAuthOk
        );
        if (active && now.saturating_sub(self.last_rx_ms) >= SESSION_LIVENESS_MS)
            || (handshaking && now.saturating_sub(self.last_begin_ms) >= HELLO_RETRY_MS)
        {
            if active {
                self.session_losses += 1;
            }
            let hello = self.session.begin();
            self.last_begin_ms = now;
            out.extend_from_slice(&encode_frame(&hello).expect("hello encodes"));
        }
        for decoded in self.decoder.push_timed(bytes, now) {
            let frame = decoded.expect("device USB bytes decode");
            let kind = frame.kind;
            let request = frame.request;
            let inbound = self.session.handle(&frame);
            for outbound in inbound.outbound {
                match outbound {
                    crate::Outbound::Raw(raw) => {
                        out.extend_from_slice(&encode_frame(&raw).expect("raw encodes"));
                    }
                    crate::Outbound::Seal(mut seal) => {
                        if self.session.protect(&mut seal).is_ok() {
                            out.extend_from_slice(&encode_frame(&seal).expect("seal encodes"));
                        }
                    }
                }
            }
            if let Some((_, node, _, network, capability)) = inbound.hello_info {
                self.hello_node = Some(node);
                self.hello_network = Some(network);
                self.hello_capability = Some(capability);
            }
            if let Some(session) = inbound.auth_session {
                self.auth_sessions.push(session);
            }
            if inbound.session_lost {
                self.session_losses += 1;
            }
            let Some(inner) = inbound.inner else { continue };
            match kind {
                FrameKind::HostOps => {
                    if authority_sub(&inner) == Some(SUB_AUTHORITY_UP) {
                        self.ups_seen += 1;
                        for up in authority.handle_up(&inner, now).expect("up assembles") {
                            completed.push((up.device, up.kind, up.bytes));
                        }
                    } else if let Some(sub) = join_relay_sub(&inner) {
                        self.route_join(sub, request, &inner, now, join, service);
                    } else {
                        self.other_host_ops += 1;
                    }
                }
                FrameKind::DataFromMesh | FrameKind::DeliveryEvent => self.data_frames += 1,
                FrameKind::Diagnostic => self.diagnostics += 1,
                _ => {}
            }
        }
        // Authority downs ride sealed HostOps frames; credit-short sends
        // stay queued for the next step (the device grants on consume).
        // 0x66 state-sets (QueryLocal/WakeLocal for the gateway itself)
        // ride alongside the 0x65 fragments — a cutover Wake to a
        // dormant gateway would otherwise never leave the host.
        for down in authority.take_ready(crate::mono_ms()) {
            let sub = authority_sub(&down.bytes);
            if sub != Some(SUB_AUTHORITY_DOWN) && sub != Some(SUB_SITE_STATE_SET) {
                continue;
            }
            self.queue_data(FrameKind::HostOps, down.bytes);
            self.downs_sent += 1;
        }
        // Join downs (0x61/0x62) ride the same queue behind them; their
        // 0x63 correlation attaches at wire time, below.
        for down in join.take_ready(crate::mono_ms()) {
            self.queue_join_down(join, down.key, down.terminal, down.bytes);
        }
        let mut kept = Vec::new();
        for mut pending in self.pending.drain(..) {
            if self.session.protect(&mut pending.frame).is_ok() {
                if let Some((adapter, key, terminal)) = pending.join_note {
                    adapter.note_sent(pending.frame.request, key, terminal);
                }
                out.extend_from_slice(&encode_frame(&pending.frame).expect("pending encodes"));
            } else {
                kept.push(pending);
                break;
            }
        }
        // `protect` consumes credit in wire order: anything after the
        // first refused frame keeps its place behind it.
        let drained: Vec<PendingFrame> = self.pending.drain(..).collect();
        kept.extend(drained);
        self.pending = kept;
        // An idle Active session gets a sealed KeepAlive on
        // KEEPALIVE_INTERVAL — the device's liveness accounting and the
        // lane's wire-quiet evidence stay honest (production
        // adapter_writer_loop parity).
        if self.session.phase == SessionPhase::Active
            && out.is_empty()
            && now.saturating_sub(self.last_tx_ms) >= KEEPALIVE_INTERVAL_MS
        {
            let mut keep = Frame {
                kind: FrameKind::KeepAlive,
                flags: 0,
                session: 0,
                request: 0,
                body: Vec::new(),
            };
            if self.session.protect(&mut keep).is_ok() {
                out.extend_from_slice(&encode_frame(&keep).expect("keepalive encodes"));
            }
        }
        if !out.is_empty() {
            self.last_tx_ms = now;
        }
        (out, completed)
    }
}

/// Phase-1 world: three Owner peers, the switch, the gateway USB host
/// end, and the provisioned site from Phase 0.
struct MeshWorld {
    peers: Vec<MeshPeer>,
    macs: [[u8; 6]; 3],
    nodes: [u64; 3],
    provision: Provision,
    usb_host: UsbHost,
    switch: Switch,
    now: u64,
    rng_state: u64,
    snaps: [MeshSnap; 3],
    /// Test-held boots: a gated peer's process is spawned but never
    /// ticked (off the air) until the test releases it. Used where a
    /// contender must wait for another peer's channel, not just a
    /// wall-clock offset.
    gate: [bool; 3],
    /// The bound join-relay adapter (ZT recovery road, D04 §5.1):
    /// Phase 0's in-process transport is retired once the mesh boots.
    join_adapter: Arc<UsbSiteAdapter>,
    /// USB incarnation shared by both adapter families (one session
    /// serves relay and authority, like the production lane); every
    /// gateway reboot, disconnect or daemon restart takes a new one.
    usb_incarnation: u64,
    /// Authenticated USB sessions across rebinds (each rebind starts
    /// a fresh `UsbHost`, so the live count alone would forget).
    usb_auth_total: u64,
    /// Delayed switch deliveries: (release_at, delivery).
    delayed: Vec<(u64, SwitchDelivery)>,
    /// C5 fault: the gateway↔host USB lane physically cut. The
    /// gateway's USB output is swallowed and the host's reply stream
    /// never reaches the bridge — buffered carriers queue like a real
    /// cable pull, and both sides' session timeouts expire naturally.
    usb_down: bool,
    /// C6: move the physical tree when the real A receipt reaches Host,
    /// before the next distributor tick may dispatch B's queued COMMIT.
    c6_flip_on_a_stored: Option<u64>,
    c6_flipped: bool,
    c7_hold_b_receipt: bool,
    c7_old_receipt: Option<(CarrierKind, Vec<u8>)>,
}

impl MeshWorld {
    /// `None` when either peer binary is missing: the test skips
    /// (ignore-equivalent). Provisions all three personas first.
    fn start(tag: &str, switch: Switch) -> Option<Self> {
        if !peers_present() {
            eprintln!(
                "SKIP site::owner_mesh_interop: no C++ peers \
                 (build routeloom_owner_mesh_peer + routeloom_joiner_interop_peer, \
                 or set ROUTELOOM_MESH_PEER / ROUTELOOM_OWNER_PEER)"
            );
            return None;
        }
        let now = now_ms();
        let mut provision = Provision::start(tag, now);
        let personas = personas();
        // Gateway first: later joins rotate the GK and the gateway's
        // mesh boot re-opens its channel like a field reboot.
        let gw_images = provision.provision_persona(&personas[0], 0xA101, Role::Gateway);
        let a_images = provision.provision_persona(&personas[1], 0xA102, Role::Relay);
        let b_images = provision.provision_persona(&personas[2], 0xA103, Role::Relay);
        let now = provision.now;
        let usb_secret_hex = hex(b"routeloom-dev-secret");
        // Staggered boots (documented harness technique, same as the HIL
        // rounds): the gateway's responder flight serializes links and a
        // contender whose M1 budget expires mid-contention has no
        // first-link re-drive yet (reported residual), so A boots 2 s in
        // and B only after A's exchange retired (~12 s). Tests that need
        // a channel-ready gate rather than a clock offset hold the peer
        // with `gate` and release it once the relay converged.
        const BOOT_OFFSETS_MS: [u64; 3] = [0, 2000, 12000];
        let mut peers = Vec::with_capacity(3);
        let images = [&gw_images, &a_images, &b_images];
        for (index, persona) in personas.iter().enumerate() {
            // Lifecycle reboots (cutover AdoptNetwork) persist the NVS
            // image here for the respawn; the site dir is removed with
            // the world.
            let nvs_save = provision
                .site
                .dir
                .join(format!("mesh-nvs-{:x}.bin", persona.node));
            peers.push(MeshPeer::spawn(
                persona,
                now + BOOT_OFFSETS_MS[index],
                0xB1E0 + index as u64,
                &images[index].0,
                &images[index].1,
                &usb_secret_hex,
                &nvs_save,
            ));
        }
        // Phase 0's in-process join transport retires here: from the
        // first mesh tick the join lane runs through the gateway's
        // real USB bytes (0x60-0x63), like the production site lane.
        // Both adapter families share incarnation 7 — the session the
        // authority adapter already holds from `Provision::start`.
        let join_adapter = UsbSiteAdapter::new(testkit::GATEWAY, 7);
        provision.site.service.set_transport(join_adapter.clone());
        let mut world = Self {
            peers,
            macs: [personas[0].mac, personas[1].mac, personas[2].mac],
            nodes: [personas[0].node, personas[1].node, personas[2].node],
            provision,
            usb_host: UsbHost::new(),
            switch,
            now,
            rng_state: 0x5EED_1234_5678_9ABC,
            snaps: Default::default(),
            gate: [false; 3],
            join_adapter,
            usb_incarnation: 7,
            usb_auth_total: 0,
            delayed: Vec::new(),
            usb_down: false,
            c6_flip_on_a_stored: None,
            c6_flipped: false,
            c7_hold_b_receipt: false,
            c7_old_receipt: None,
        };
        // The USB Hello goes out before the first tick; the gateway
        // answers from its pump.
        let hello = world.usb_host.hello_bytes(world.now);
        world.peers[0].send_usb(&hello);
        Some(world)
    }

    /// Authenticated gateway USB sessions so far, across rebinds.
    fn usb_auth_total(&self) -> usize {
        self.usb_auth_total as usize + self.usb_host.auth_sessions.len()
    }

    /// A gateway USB session boundary (reboot, disconnect, daemon
    /// restart): the old session's relays, queues and request mappings
    /// die with their adapters — nothing is carried over and no
    /// adapter is reused across the boundary (production `site_once`
    /// parity, D04 §5.1). The gateway re-authenticates from the fresh
    /// Hello this queues.
    fn gateway_usb_rebind(&mut self) {
        self.usb_auth_total += self.usb_host.auth_sessions.len() as u64;
        self.join_adapter.close();
        let _ = self
            .provision
            .site
            .service
            .with(|a| a.drop_gateway_relays(testkit::GATEWAY, self.now));
        self.provision.usb.close();
        self.usb_host = UsbHost::new();
        self.usb_incarnation += 1;
        let incarnation = self.usb_incarnation;
        let join = UsbSiteAdapter::new(testkit::GATEWAY, incarnation);
        self.provision.site.service.set_transport(join.clone());
        self.join_adapter = join;
        let usb = UsbAuthorityAdapter::new(testkit::GATEWAY, incarnation);
        self.provision
            .site
            .service
            .set_authority_transport(Some(usb.clone()));
        self.provision.usb = usb;
        let (site_epoch, rs_epoch, gk_epoch) = self.provision.site.service.authority_epochs();
        let _ = self
            .provision
            .usb
            .query_local(site_epoch, rs_epoch, gk_epoch);
        let hello = self.usb_host.hello_bytes(self.now);
        self.peers[0].send_usb(&hello);
    }

    fn usb_disconnect(&mut self) {
        self.usb_down = true;
        self.join_adapter.close();
        self.provision.usb.close();
        let _ = self
            .provision
            .site
            .service
            .with(|a| a.drop_gateway_relays(testkit::GATEWAY, self.now));
        self.provision.site.service.set_authority_transport(None);
    }

    fn usb_reconnect(&mut self) {
        self.usb_down = false;
        self.gateway_usb_rebind();
    }

    fn daemon_restart(&mut self) {
        self.join_adapter.close();
        self.provision.usb.close();
        self.provision.site.restart(self.now);
        self.gateway_usb_rebind();
    }

    fn deliver_authority_up(&mut self, device: u64, kind: CarrierKind, bytes: &[u8], at: u64) {
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
        self.provision.site.service.handle_authority_up(
            device,
            kind,
            bytes,
            HostTime::sync(at),
            &mut rng,
        );
        self.rng_state = state;
    }

    /// One virtual step: tick every booted peer, switch the radio
    /// frames, pump the gateway USB into the authority, tick the
    /// authority. Peers whose boot time has not come are off the air:
    /// their MACs do not exist yet and frames to them drop.
    fn step(&mut self, dt_ms: u64) {
        self.now += dt_ms;
        let gate = self.gate;
        let mut ticks = Vec::with_capacity(3);
        for (index, peer) in self.peers.iter_mut().enumerate() {
            if !peer.booted && self.now >= peer.t0 && !gate[index] {
                peer.booted = true;
            }
            ticks.push(if peer.booted {
                Some(peer.tick(self.now))
            } else {
                None
            });
        }
        // A rebooted gateway answers on a fresh USB session: a full
        // session boundary (fresh host end, fresh adapters, the
        // gateway re-authenticates from the new Hello).
        if !self.usb_down && ticks[0].as_ref().is_some_and(|t| t.rebooted) {
            self.gateway_usb_rebind();
        }
        // Switch: deliver per audibility + same channel, then report
        // MAC ACKs (unicast succeeds iff delivered).
        let booted = [ticks[0].is_some(), ticks[1].is_some(), ticks[2].is_some()];
        let channels = [
            ticks[0].as_ref().map(|t| t.snap.channel).unwrap_or(0),
            ticks[1].as_ref().map(|t| t.snap.channel).unwrap_or(0),
            ticks[2].as_ref().map(|t| t.snap.channel).unwrap_or(0),
        ];
        let mut deliveries: Vec<SwitchDelivery> = Vec::new();
        let mut completions: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        // Frames a delayed leg holds this step (released by the clock,
        // below — a reconnect never replays what a down leg dropped,
        // but a live delayed leg keeps what it held).
        let mut hold: Vec<(u64, SwitchDelivery)> = Vec::new();
        // A directed leg eats one frame: drop budgets hit before the
        // audibility check (an armed loss fires even on a live leg;
        // the counters prove which rule ate what).
        for (from, tick) in ticks.iter().enumerate() {
            let Some(tick) = tick else { continue };
            for tx in &tick.tx {
                self.switch
                    .c7_observe(from, tx.dst_mac, &tx.bytes, self.macs[2]);
                if tx.dst_mac == BROADCAST_MAC {
                    completions[from].push(1);
                    for to in 0..3 {
                        if to != from
                            && booted[to]
                            && self.switch.audible[from][to]
                            && channels[to] == channels[from]
                        {
                            deliveries.push((to, self.macs[from], BROADCAST_MAC, tx.bytes.clone()));
                            self.switch.delivered += 1;
                            self.switch.leg_delivered[from][to] += 1;
                        }
                    }
                    continue;
                }
                let Some(to) = (0..3).find(|to| self.macs[*to] == tx.dst_mac) else {
                    completions[from].push(0);
                    self.switch.dropped += 1;
                    continue;
                };
                let leg_up = to != from
                    && booted[to]
                    && self.switch.audible[from][to]
                    && channels[to] == channels[from];
                let notice_chunk = from == 2 && to == 1 && notice_object_frame(&tx.bytes, 50);
                let old_data = from == 1
                    && to == 2
                    && self.switch.c7_hold_data
                    && tx.bytes.len() > 5
                    && tx.bytes[..4] == *b"RL\x02\0"
                    && tx.bytes[4] == 16;
                if old_data {
                    completions[from].push(0);
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else if self.switch.drop_notice_chunks && notice_chunk {
                    self.switch.notice_chunks_dropped += 1;
                    completions[from].push(0);
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else if self.switch.drop_next[from][to] > 0 {
                    self.switch.drop_next[from][to] -= 1;
                    completions[from].push(0);
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else if !leg_up {
                    completions[from].push(0);
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else {
                    if from == 2 && to == 1 && notice_object_frame(&tx.bytes, 49) {
                        self.switch.notice_manifests_delivered += 1;
                    }
                    // The frame crosses (now or after the leg's hold);
                    // only the MAC ACK is droppable from here.
                    let release_at = self.now + self.switch.delay_ms[from][to];
                    let delivery = (to, self.macs[from], tx.dst_mac, tx.bytes.clone());
                    if release_at <= self.now {
                        deliveries.push(delivery);
                    } else {
                        hold.push((release_at, delivery));
                    }
                    if self.switch.ack_drop_next[from][to] > 0 {
                        self.switch.ack_drop_next[from][to] -= 1;
                        completions[from].push(0);
                    } else {
                        completions[from].push(1);
                    }
                    self.switch.leg_delivered[from][to] += 1;
                    self.switch.delivered += 1;
                }
            }
        }
        self.delayed.extend(hold);
        // Delayed legs release by the clock; the release re-checks
        // nothing (airtime already spent).
        let mut still: Vec<(u64, SwitchDelivery)> = Vec::new();
        for (release_at, delivery) in self.delayed.drain(..) {
            if release_at <= self.now {
                deliveries.push(delivery);
            } else {
                still.push((release_at, delivery));
            }
        }
        self.delayed = still;
        for (to, src, dst, bytes) in &deliveries {
            self.peers[*to].send_rx(src, dst, bytes);
        }
        for (index, peer) in self.peers.iter_mut().enumerate() {
            if booted[index] {
                peer.send_complete(&completions[index]);
            }
        }
        // Gateway USB into the authority (the gateway always boots first).
        let adapter = self.provision.usb.clone();
        let join = self.join_adapter.clone();
        let gw_usb = if self.usb_down {
            &[][..]
        } else {
            ticks[0].as_ref().map(|t| t.usb.as_slice()).unwrap_or(&[])
        };
        let (usb_out, completed) = self.usb_host.pump(
            gw_usb,
            self.now,
            &adapter,
            &join,
            &self.provision.site.service,
        );
        if !self.usb_down {
            self.peers[0].send_usb(&usb_out);
        }
        for (device, kind, bytes) in completed {
            if self.c7_hold_b_receipt
                && device == NODE_B
                && kind == CarrierKind::Envelope
                && ticks[2].as_ref().is_some_and(|tick| tick.snap.phase == 11)
                && self
                    .provision
                    .site
                    .service
                    .with(|a| {
                        a.channels
                            .lock()
                            .unwrap()
                            .is_commit_stored_envelope(device, &bytes)
                    })
                    .0
            {
                if self.c7_old_receipt.is_none() {
                    self.c7_old_receipt = Some((kind, bytes));
                }
                continue;
            }
            self.deliver_authority_up(device, kind, &bytes, self.now);
        }
        if self.c6_flip_on_a_stored.is_some_and(|op| {
            self.provision
                .site
                .service
                .with(|a| {
                    a.cutover_routes
                        .get(&(op, NODE_A))
                        .is_some_and(|plan| plan.stored)
                })
                .0
        }) {
            self.switch.set_audible(0, 2, false);
            self.switch.set_audible(2, 0, false);
            self.switch.set_audible(0, 1, true);
            self.switch.set_audible(1, 0, true);
            self.c6_flip_on_a_stored = None;
            self.c6_flipped = true;
        }
        self.provision.now = self.now;
        self.provision.site.service.tick(HostTime::sync(self.now));
        let _ = self
            .provision
            .site
            .kguard
            .serve_once(&self.provision.site.link);
        for (index, tick) in ticks.iter().enumerate() {
            if let Some(tick) = tick {
                self.snaps[index] = tick.snap.clone();
            }
        }
    }

    fn pump_until(&mut self, budget_ticks: u32, done: impl Fn(&[MeshSnap; 3]) -> bool) {
        // 25 ms steps: the discovery offer window is 160 ms and the
        // switch adds one step of air latency, so 100 ms steps would
        // expire every offer (a harness artifact, not a device bug).
        for _ in 0..budget_ticks {
            self.step(25);
            if done(&self.snaps) {
                return;
            }
        }
    }

    fn member_row(&self, node: u64) -> Option<super::store::DeviceRow> {
        self.provision
            .site
            .service
            .with(|a| a.devices.get(&node).cloned())
            .0
    }

    fn active_gk(&self) -> u32 {
        self.provision.site.service.with(|a| a.gks.active_epoch()).0
    }

    /// One cutover op's live targets: (node, state, prepared_revision,
    /// attempts) — the production record, for dispatch-ordering
    /// evidence (C1: a relay's COMMIT leaves only after its leaf's
    /// COMMIT_STORED lands).
    fn cutover_targets(&self, operation_id: &str) -> Vec<(u64, String, u32, u32)> {
        use super::cutover::GrantState;
        let op = super::records::parse_op_token(operation_id).unwrap();
        self.provision
            .site
            .service
            .with(|a| {
                a.operations
                    .get(&op)
                    .and_then(|record| record.cutover.as_ref())
                    .map(|state| {
                        state
                            .targets
                            .iter()
                            .map(|t| {
                                let name = match t.state {
                                    GrantState::Pending => "pending",
                                    GrantState::Unknown => "unknown",
                                    GrantState::Prepared => "prepared",
                                    GrantState::Applied => "applied",
                                    GrantState::Recovered => "recovered",
                                    GrantState::Retired => "retired",
                                };
                                (t.node, name.to_string(), t.prepared_revision, t.attempts)
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .0
    }

    /// One target's live route plan (report/stored/deferred), if the
    /// cutover tracks it — the RAM the scheduler actually steers by.
    fn cutover_route(
        &self,
        operation_id: &str,
        node: u64,
    ) -> Option<super::cutover::CutoverRoutePlan> {
        let op = super::records::parse_op_token(operation_id).unwrap();
        self.provision
            .site
            .service
            .with(|a| a.cutover_routes.get(&(op, node)).cloned())
            .0
    }

    /// One revoke op's notice evidence: (delivery, intent_confirmed).
    /// `None` while the op carries no notice (or no such op).
    fn revoke_notice(&self, operation_id: &str) -> Option<(String, bool)> {
        use super::revocation::NoticeDelivery;
        let op = super::records::parse_op_token(operation_id).unwrap();
        self.provision
            .site
            .service
            .with(|a| {
                a.operations.get(&op).and_then(|record| {
                    record.notice.as_ref().map(|notice| {
                        let delivery = match notice.delivery {
                            NoticeDelivery::Pending => "pending",
                            NoticeDelivery::Sent => "sent",
                            NoticeDelivery::Unreachable => "unreachable",
                        };
                        (delivery.to_string(), notice.intent_confirmed)
                    })
                })
            })
            .0
    }
}

// --- Tests ---------------------------------------------------------------------

/// Phase-1 convergence on the direct radio: all three Owners adopt
/// from their Phase-0 images (member boots, no rejoins), open their
/// authority channels through the gateway's real USB relay, confirm,
/// and exchange app traffic over the real mesh.
#[test]
fn mesh_direct_converges_and_delivers() {
    let Some(mut world) = MeshWorld::start("direct", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    // Member boots: the adopted network matches the site, the lifecycle
    // is Active, the channels are ready and the joins confirmed — with
    // the gateway USB session authenticated for real.
    world.pump_until(6000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
                && s.has_site
        })
    });
    let active = world.active_gk();
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.mode, MODE_MEMBER, "peer {index} adopted");
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active");
        assert!(snap.authority_ready, "peer {index} channel ready");
        assert!(snap.join_confirmed, "peer {index} confirmed");
        assert!(snap.has_site, "peer {index} holds its site");
        assert!(snap.has_identity, "peer {index} holds its identity");
        assert!(snap.stores_healthy, "peer {index} stores healthy");
        assert_eq!(snap.site_generation, 1, "peer {index} generation");
        assert_eq!(snap.gk_current, active, "peer {index} on the active GK");
        assert_eq!(
            snap.adopted_network,
            testkit::network(),
            "peer {index} on the site network"
        );
        assert!(snap.sends > 0, "peer {index} used its radio");
    }
    // Real pairwise sessions came up, not just the authority lane.
    assert!(
        world.snaps[1].link_sessions > 0 && world.snaps[1].end_sessions > 0,
        "member A sessions: {:?}",
        world.snaps[1]
    );
    assert!(world.switch.delivered > 0, "frames crossed the switch");
    assert_eq!(
        world.switch.dropped, 0,
        "direct radio drops nothing: {}",
        world.switch.dropped
    );
    assert_eq!(
        world.usb_host.auth_sessions.len(),
        1,
        "one gateway USB session, no re-hello loop"
    );
    assert_eq!(world.usb_host.hello_node, Some(testkit::GATEWAY));
    assert_eq!(world.usb_host.hello_network, Some(testkit::network()));
    assert_eq!(world.usb_host.hello_capability, Some(USB_CAP));
    assert_eq!(world.usb_host.session_losses, 0, "USB session held");
    assert!(
        world.usb_host.ups_seen > 0 && world.usb_host.downs_sent > 0,
        "authority carriers crossed the real USB both ways"
    );
    assert_eq!(world.snaps[0].usb_state, USB_ACTIVE);
    for node in world.nodes {
        let row = world.member_row(node).expect("member row");
        assert!(row.member && row.confirmed, "node {node:x} confirmed");
    }
    // App traffic member A -> member B over the real mesh.
    let payload = b"mesh-direct-hello";
    world.peers[1].app_send(NODE_B, payload);
    world.pump_until(3000, |snaps| {
        snaps[2].rx_count > 0
            && snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    assert_eq!(world.snaps[2].rx_src, NODE_A);
    assert_eq!(&world.snaps[2].rx[..payload.len()], payload);
}

/// Forced multi-hop: A and the gateway cannot hear each other, so
/// A<->gateway traffic and A's authority channel relay via B. Delivery
/// through the switch proves the relay — direct frames cannot exist.
#[test]
fn mesh_forced_multihop_relays() {
    let Some(mut world) = MeshWorld::start("multihop", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    // A hears only B, and B's responder flight is held by its own
    // gateway link/end exchanges until its channel is ready; an M1
    // parked that long exhausts the initiator budget with no
    // first-link re-drive yet (reported residual). Hold A off the air
    // until the relay converged, then boot it into a free flight.
    world.gate[1] = true;
    world.pump_until(9000, |snaps| {
        snaps[0].authority_ready && snaps[2].authority_ready && snaps[2].join_confirmed
    });
    assert!(
        world.snaps[2].authority_ready && world.snaps[2].join_confirmed,
        "relay B ready before A boots: {:?}",
        world.snaps[2]
    );
    world.gate[1] = false;
    world.pump_until(9000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
        })
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.mode, MODE_MEMBER, "peer {index} adopted");
        assert!(snap.authority_ready, "peer {index} channel ready");
        assert!(snap.join_confirmed, "peer {index} confirmed");
    }
    // A -> gateway app traffic must relay via B.
    let payload = b"mesh-multihop-hello";
    world.peers[1].app_send(testkit::GATEWAY, payload);
    world.pump_until(3000, |snaps| {
        snaps[0].rx_count > 0
            && snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "A->gateway delivered via relay: {:?}",
        world.snaps[1].app_tx
    );
    assert_eq!(world.snaps[0].rx_src, NODE_A);
    assert_eq!(&world.snaps[0].rx[..payload.len()], payload);
}

/// #168 GK over the real mesh: a manual rotation stages, members ACK,
/// and the new epoch goes active on every node (no `catching_up`).
#[test]
fn mesh_group_key_rotate_acknowledged() {
    use routeloom_client::site::SiteAdmin;
    let Some(mut world) = MeshWorld::start("gk", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    world.pump_until(6000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
        })
    });
    assert!(
        world.snaps.iter().all(|s| s.authority_ready),
        "mesh converged before rotate"
    );
    let before: Vec<u32> = world.snaps.iter().map(|s| s.gk_current).collect();

    let active = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status")
        .active;
    let outcome = world
        .provision
        .site
        .link
        .rotate_group_key(active, "mesh-gk-1")
        .expect("rotate commits");
    assert_eq!(outcome.state, "committed");

    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.gk_current == outcome.to_epoch)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.gk_current, outcome.to_epoch,
            "peer {index} active GK advanced from {}: {snap:?}",
            before[index]
        );
    }
    // Active ACKs ride the authority channel behind the apply; let them
    // settle before reading the converged phase.
    for _ in 0..120 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .group_key_status()
            .expect("gk status")
            .phase;
        if phase == "stable" {
            break;
        }
    }
    let status = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status");
    assert_eq!(status.active, outcome.to_epoch);
    assert!(
        status.phase == "stable",
        "rotation converged, not catching_up: {status:?}"
    );
}

/// #168 cutover over the real mesh: stage epoch+1, every node (real
/// gateway included) prepares over its own channel, the commit lands
/// past the window, all adopt the new network/GK, re-open channels
/// (USB re-auth), and new-epoch traffic flows with no straggler.
#[test]
fn mesh_cutover_prepare_commit_applied() {
    use routeloom_client::site::SiteAdmin;
    use routeloom_provision::signer::FileRootSigner;
    let Some(mut world) = MeshWorld::start("cutover", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    world.pump_until(6000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
        })
    });
    assert!(
        world.snaps.iter().all(|s| s.authority_ready),
        "mesh converged before cutover"
    );

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
    // Stage through the service with the virtual clock: the API socket
    // stamps operations with the process monotonic clock while the
    // harness ticks the authority on wall-based virtual time, which
    // would lapse the 600 s prepare window instantly (harness-only
    // clock mixup — the production daemon runs one clock).
    let staged_at = world.now;
    let outcome_json = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover(
                501,
                super::cutover::CutoverRequest {
                    expected_site_epoch: testkit::SITE_EPOCH,
                    next_site_cert: next_cert.clone(),
                    key: "mesh-cut-1".into(),
                },
                HostTime::sync(world.now),
            )
        })
        .0
        .expect("cutover stages");
    let outcome_value: routeloom_json::Json =
        routeloom_json::parse(&outcome_json).expect("outcome parses");
    assert_eq!(
        outcome_value.get("state").and_then(|v| v.as_str()),
        Some("preparing")
    );
    let operation_id = outcome_value
        .get("operation_id")
        .and_then(|v| v.as_str())
        .expect("operation id")
        .to_string();

    // PREPARE lands over each channel; every node stages the epoch.
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }

    // The peers' PREPARE receipts are still in flight when they stage:
    // drain them at 25 ms until the Owner has seen every target's
    // receipt before fast-forwarding. A queued carrier debits its
    // routed TTL while it waits, and a 1 s step ages it past the
    // receiver's dead-on-arrival gate — the same harness artifact as
    // the commit legs below.
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }

    // Past the window the commit lands; all adopt the new network,
    // its GK, and re-open the channel there (USB re-auth included).
    // The stable window fast-forwards in 1 s steps ONLY while the
    // air is silent: a 1 s step stamps a full second of RX age on
    // every delivered frame, and one that also carries send-queue
    // delay dies on the receiver's dead-on-arrival gate — the same
    // harness artifact as the commit legs below (the design
    // promises no radio that jumps). Busy air ticks at 25 ms.
    let window_end = staged_at + super::cutover::CUTOVER_PREPARE_WINDOW_MS;
    let mut quiet_ms = 0u64;
    while world.now + 10_000 < window_end {
        let delivered_before = world.switch.delivered;
        let jump = quiet_ms >= 3_000;
        world.step(if jump { 1_000 } else { 25 });
        quiet_ms = if world.switch.delivered == delivered_before {
            quiet_ms.saturating_add(if jump { 1_000 } else { 25 })
        } else {
            0
        };
    }
    for _ in 0..4000 {
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase != "preparing" && phase != "waiting_gateway" {
            break;
        }
        world.step(25);
    }
    let (next_gk, new_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = super::records::parse_op_token(&operation_id).unwrap();
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.new_network)
        })
        .0;
    // Adoption converges when the peers are Active on the new
    // network/GK with re-opened channels AND their APPLIEDs landed: a
    // fresh Ready still has its APPLIED in flight (relay + USB +
    // authority ticks behind), so peer convergence alone is too eager.
    for _ in 0..8000 {
        world.step(25);
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done {
            let applied = world
                .provision
                .site
                .link
                .cutover_operation(&operation_id)
                .unwrap()
                .map(|p| p.applied)
                .unwrap_or(0);
            if applied == 3 {
                break;
            }
        }
    }
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(
            snap.authority_ready,
            "peer {index} channel re-open: {snap:?}"
        );
    }
    // No straggler: every target applied, no recovery parking.
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    assert!(
        !progress.recovery_pending,
        "no straggler parked: {progress:?}"
    );
    assert_eq!(progress.applied, 3, "all targets applied: {progress:?}");
    // Adoption reboots exactly once per peer (#168: the retired
    // AdoptNetwork must reboot, never wait and never loop), and the
    // rebooted gateway re-authenticates its USB session (HIL R4).
    assert_eq!(
        [
            world.peers[0].reboots,
            world.peers[1].reboots,
            world.peers[2].reboots
        ],
        [1, 1, 1],
        "one adoption reboot each"
    );
    assert_eq!(
        world.usb_auth_total(),
        2,
        "gateway USB re-authenticated after its reboot"
    );

    // New-epoch traffic flows member to member.
    let payload = b"mesh-cutover-hello";
    world.peers[1].app_send(NODE_B, payload);
    world.pump_until(3000, |snaps| {
        snaps[2].rx_count > 0
            && snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "new-epoch A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    assert_eq!(&world.snaps[2].rx[..payload.len()], payload);
}

/// Shared convergence: every peer adopted, Active, channel-ready
/// and JoinConfirmed.
fn converge(world: &mut MeshWorld, what: &str) {
    world.pump_until(6000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
        })
    });
    assert!(
        world.snaps.iter().all(|s| s.authority_ready),
        "mesh converged before {what}"
    );
}

/// Forced-multihop convergence with one peer held off the air until
/// the relay converged (the M1-budget technique from
/// `mesh_forced_multihop_relays`): `gated` boots into a free flight.
fn converge_gated(world: &mut MeshWorld, gated: usize, what: &str) {
    world.gate[gated] = true;
    world.pump_until(9000, |snaps| {
        snaps
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != gated)
            .all(|(_, s)| s.authority_ready && s.join_confirmed)
    });
    assert!(
        world
            .snaps
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != gated)
            .all(|(_, s)| s.authority_ready),
        "relay converged before {what}"
    );
    world.gate[gated] = false;
    converge(world, what);
}

/// R1 (§5.2): notice versus prompt refusal on forced G—B—A. A is
/// revoked while its notice transfer is stalled mid-chunk; the
/// survivors must enforce first (no waiting on the notice timeout),
/// refuse A's traffic on every leg, keep their own delivery healthy,
/// and A must still erase — via the resumed direct send when it wins
/// the race, else over the ZT road. `stall` selects the main
/// condition (stalled) or the control (plain direct race).
fn r1_once(tag: &str, stall: bool) {
    use routeloom_client::site::{RemovalReason, SiteAdmin};
    let Some(mut world) = MeshWorld::start(tag, Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "r1 revoke");
    let id_fp_before = world.snaps[1].id_fp;
    assert_ne!(id_fp_before, 0, "A holds an identity fingerprint");
    // Pre-revoke delivery works (and brings the A-B E2E up, so its
    // later retirement is observable rather than vacuous).
    world.peers[1].app_send(NODE_B, b"r1-before");
    world.pump_until(3000, |snaps| {
        snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "pre-revoke A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    let delivered_before = world.snaps[1]
        .app_tx
        .iter()
        .filter(|tx| tx.state == DELIVERY_DELIVERED)
        .count();
    let gw_rrs = world.snaps[0].rrs_applied;
    let b_rrs = world.snaps[2].rrs_applied;
    let b_link = world.snaps[2].link_sessions;
    let b_end = world.snaps[2].end_sessions;

    let row = world.member_row(NODE_A).expect("member row");
    let outcome = world
        .provision
        .site
        .link
        .revoke(NODE_A, row.generation, RemovalReason::Removed, tag)
        .expect("revoke commits");
    assert_eq!(outcome.state, "committed");
    if stall {
        // The revoke committed a Notice for A. Keep its chunk off the
        // B→A leg while its manifest and unrelated radio traffic pass.
        world.switch.drop_notice_chunks = true;
    }

    // Enforcement first: both survivors apply the RRS while the
    // notice is still unconfirmed and A still holds its site.
    let mut notice_live_at_rrs = false;
    for _ in 0..8000 {
        let was_g = world.snaps[0].rrs_applied;
        let live_before_g = world.snaps[0].notice_down_live;
        world.step(25);
        if world.snaps[0].rrs_applied > was_g {
            notice_live_at_rrs = live_before_g
                && world.switch.notice_manifests_delivered > 0
                && world.switch.notice_chunks_dropped > 0
                && world.snaps[1].phase == PHASE_ACTIVE;
        }
        if world.snaps[0].rrs_applied > gw_rrs && world.snaps[2].rrs_applied > b_rrs {
            break;
        }
    }
    assert!(
        world.snaps[0].rrs_applied > gw_rrs,
        "gateway enforced: {:?}",
        world.snaps[0]
    );
    assert!(
        world.snaps[2].rrs_applied > b_rrs,
        "relay B enforced: {:?}",
        world.snaps[2]
    );
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "enforced with the notice still unconfirmed: {notice:?}"
    );
    if stall {
        assert!(
            notice_live_at_rrs,
            "gateway had A's Notice down slot when RRS enforced"
        );
        assert_eq!(world.snaps[1].phase, PHASE_ACTIVE, "A still active at RRS");
        assert!(
            world.snaps[1].has_site,
            "A holds site during Notice transfer"
        );
        assert!(
            world.switch.notice_manifests_delivered > 0,
            "the Notice manifest reached A before the stalled chunk"
        );
        assert!(
            world.switch.notice_chunks_dropped > 0,
            "the stall ate a Notice chunk, not unrelated radio traffic"
        );
    }
    // The enforcement retired A's contexts on the relay that held
    // them (not a mere RX hush: the sessions are gone). The gateway
    // never held an A session (deaf by topology); its refusal shows
    // on the relayed A->gateway leg below.
    assert!(
        world.snaps[2].link_sessions < b_link,
        "relay retired A's link: {} -> {}",
        b_link,
        world.snaps[2].link_sessions
    );
    assert!(
        world.snaps[2].end_sessions < b_end,
        "relay retired A's E2E: {} -> {}",
        b_end,
        world.snaps[2].end_sessions
    );
    let gw_est = world.snaps[0].link_established + world.snaps[0].end_established;
    let b_est = world.snaps[2].link_established + world.snaps[2].end_established;
    let gw_rx = world.snaps[0].rx_count;
    let b_rx = world.snaps[2].rx_count;

    // Refusal on every leg: A keeps sending (it does not know yet),
    // nothing new is admitted, while the survivors still deliver to
    // each other. (Well before any ZT: the revoked road takes ~13
    // virtual minutes to even start asking.)
    // (A peer tracks 16 app sends per lifetime.)
    for round in 0..3 {
        // Alternate the direct and the relayed revoked leg.
        let dst = if round % 2 == 0 {
            NODE_B
        } else {
            testkit::GATEWAY
        };
        world.peers[1].app_send(dst, b"r1-revoked-data");
        world.peers[2].app_send(testkit::GATEWAY, b"r1-healthy-data");
        for _ in 0..40 {
            world.step(25);
        }
        let delivered_now = world.snaps[1]
            .app_tx
            .iter()
            .filter(|tx| tx.state == DELIVERY_DELIVERED)
            .count();
        assert_eq!(
            delivered_now, delivered_before,
            "round {round}: no revoked A send delivered: {:?}",
            world.snaps[1].app_tx
        );
    }
    assert_eq!(
        world.snaps[2].rx_count, b_rx,
        "B took no app RX from revoked A"
    );
    // The gateway's RX grew by exactly B's 3 healthy sends — A's
    // relayed send never arrived (B drops revoked origins).
    assert_eq!(
        world.snaps[0].rx_count,
        gw_rx + 3,
        "gateway RX is exactly the survivors' traffic"
    );
    assert_eq!(
        world.snaps[0].rx_src, NODE_B,
        "gateway RX came from survivor B"
    );
    assert_eq!(
        world.snaps[0].link_established + world.snaps[0].end_established,
        gw_est,
        "gateway admitted no new session from A"
    );
    assert_eq!(
        world.snaps[2].link_established + world.snaps[2].end_established,
        b_est,
        "relay admitted no new session from A"
    );
    assert!(
        world.snaps[2]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "survivor B->gateway still delivers: {:?}",
        world.snaps[2].app_tx
    );
    // The stall served its purpose (enforcement under a live notice
    // slot): let the recovery path use the radio again.
    world.switch.drop_notice_chunks = false;

    // Erasure, by whichever road won: the resumed direct send lands
    // Removing in seconds; the ZT road needs A's own retries — a
    // revoked device whose app keeps sending re-discovers, hears the
    // survivors' newer-generation offers, strikes out and re-verifies
    // (04 §3.5). The loop keeps both legs honest: A's retries must
    // never deliver, the survivors' traffic must.
    let mut chatter_rounds = 0_u32;
    for i in 0..48000 {
        world.step(25);
        if world.snaps[1].phase == PHASE_HOLDOFF {
            break;
        }
        // Every 30 s of virtual time: A retries (its app does not
        // know yet) while the survivors keep ordinary mesh activity
        // — delivered traffic plus an unanswered discovery round, the
        // chatter a live radio carries and A's newer-generation
        // evidence rides on (04 §3.5).
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            let a_dst = if chatter_rounds % 2 == 0 {
                NODE_B
            } else {
                NODE_GHOST
            };
            world.peers[1].app_send(a_dst, b"r1-retry");
            let b_dst = if chatter_rounds % 2 == 0 {
                testkit::GATEWAY
            } else {
                NODE_GHOST
            };
            world.peers[2].app_send(b_dst, b"r1-chatter");
        }
    }
    let a = &world.snaps[1];
    assert_eq!(a.phase, PHASE_HOLDOFF, "A holdoff: {a:?}");
    assert!(!a.has_site, "A erased its site trust");
    assert!(
        a.holdoff_remaining_ms > 0,
        "holdoff runs after erasure: {}",
        a.holdoff_remaining_ms
    );
    assert_eq!(
        a.id_fp, id_fp_before,
        "revocation leaves the RLI1 fingerprint untouched"
    );
}

#[test]
fn mesh_r1_notice_and_prompt_refusal() {
    // Main condition: the notice stalls mid-chunk while RRS enforces.
    r1_once("r1-stall", true);
    // Control: the same race unstalled — enforcement-first and
    // erasure hold either way; only the winning road may differ.
    r1_once("r1-control", false);
}

/// Drives a revoked A to its end state over whichever road wins (the
/// resumed direct send or the ZT verify): holdoff with the site
/// erased and the identity fingerprint untouched. Same shape as R1's
/// loop — A retries while the survivors chatter, so a live radio's
/// newer-generation evidence keeps arriving (§3.5).
fn revoked_a_to_holdoff(world: &mut MeshWorld, tag: &str, id_fp_before: u64) {
    let mut saw_removing = world.snaps[1].phase == PHASE_REMOVING;
    let mut chatter_rounds = 0_u32;
    for i in 0..48000 {
        world.step(25);
        saw_removing |= world.snaps[1].phase == PHASE_REMOVING;
        if world.snaps[1].phase == PHASE_HOLDOFF {
            break;
        }
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            let a_dst = if chatter_rounds % 2 == 0 {
                NODE_B
            } else {
                NODE_GHOST
            };
            world.peers[1].app_send(a_dst, b"r2-retry");
            let b_dst = if chatter_rounds % 2 == 0 {
                testkit::GATEWAY
            } else {
                NODE_GHOST
            };
            world.peers[2].app_send(b_dst, b"r2-chatter");
        }
    }
    let a = &world.snaps[1];
    assert_eq!(a.phase, PHASE_HOLDOFF, "{tag}: A holdoff: {a:?}");
    assert!(!a.has_site, "{tag}: A erased its site trust");
    assert!(
        a.holdoff_remaining_ms > 0,
        "{tag}: holdoff runs after erasure: {}",
        a.holdoff_remaining_ms
    );
    assert_eq!(
        a.id_fp, id_fp_before,
        "{tag}: revocation leaves the RLI1 fingerprint untouched"
    );
    assert!(saw_removing, "{tag}: A passed through Removing");
}

/// R2 (§5.2): revoke while the target cannot be reached, expire the
/// 60 s direct-send window, then reconnect. `group` selects the
/// variant: only A isolated (the survivors enforce during the
/// outage), or B/A isolated from G as one group (in-group traffic
/// survives the revoke, B enforces only after the heal). Either way
/// the survivors' RRS/GK advance without the notice confirmation,
/// the outage never counts as reached, and A ends erased via ZT.
fn r2_once(tag: &str, group: bool) {
    use routeloom_client::site::{RemovalReason, SiteAdmin};
    let Some(mut world) = MeshWorld::start(tag, Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "r2 revoke");
    let id_fp_before = world.snaps[1].id_fp;
    assert_ne!(id_fp_before, 0, "A holds an identity fingerprint");
    // Pre-revoke delivery works (and brings the A-B E2E up, so the
    // later refusal is observable rather than vacuous).
    world.peers[1].app_send(NODE_B, b"r2-before");
    world.pump_until(3000, |snaps| {
        snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "pre-revoke A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    let delivered_before = world.snaps[1]
        .app_tx
        .iter()
        .filter(|tx| tx.state == DELIVERY_DELIVERED)
        .count();
    let gw_rrs = world.snaps[0].rrs_applied;
    let b_rrs = world.snaps[2].rrs_applied;
    let gk0 = world.active_gk();

    if group {
        world.switch.isolate(0);
    } else {
        world.switch.isolate(1);
    }
    let row = world.member_row(NODE_A).expect("member row");
    let outcome = world
        .provision
        .site
        .link
        .revoke(NODE_A, row.generation, RemovalReason::Removed, tag)
        .expect("revoke commits");
    assert_eq!(outcome.state, "committed");

    if group {
        // The gateway enforces over its local USB channel while its
        // radio is cut; the island hears nothing yet.
        world.pump_until(8000, |snaps| snaps[0].rrs_applied > gw_rrs);
        assert!(
            world.snaps[0].rrs_applied > gw_rrs,
            "gateway enforced while cut: {:?}",
            world.snaps[0]
        );
        for _ in 0..200 {
            world.step(25);
        }
        assert_eq!(
            world.snaps[2].rrs_applied, b_rrs,
            "island B holds no RRS yet"
        );
        // In-group traffic survives the revoke (04 §6.2): B never saw
        // the RRS, so the old link still delivers.
        world.peers[1].app_send(NODE_B, b"r2-island");
        world.pump_until(3000, |snaps| {
            snaps[1]
                .app_tx
                .iter()
                .filter(|tx| tx.state == DELIVERY_DELIVERED)
                .count()
                > delivered_before
        });
        let delivered_island = world.snaps[1]
            .app_tx
            .iter()
            .filter(|tx| tx.state == DELIVERY_DELIVERED)
            .count();
        assert!(
            delivered_island > delivered_before,
            "in-group A->B delivers after the revoke: {:?}",
            world.snaps[1].app_tx
        );
    } else {
        // Both survivors enforce while the notice to A cannot move.
        world.pump_until(8000, |snaps| {
            snaps[0].rrs_applied > gw_rrs && snaps[2].rrs_applied > b_rrs
        });
        assert!(
            world.snaps[0].rrs_applied > gw_rrs,
            "gateway enforced: {:?}",
            world.snaps[0]
        );
        assert!(
            world.snaps[2].rrs_applied > b_rrs,
            "relay B enforced: {:?}",
            world.snaps[2]
        );
    }
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "enforced with the notice still unconfirmed: {notice:?}"
    );
    // The revoke-driven GK rotation advances on the reachable side
    // without the notice confirmation (the gateway only, in the group
    // variant — the island holds the old key).
    let gk1 = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status")
        .active;
    assert!(gk1 > gk0, "the revoke rotated the GK: {gk0} -> {gk1}");
    world.pump_until(8000, |snaps| {
        snaps[0].gk_current == gk1 && (group || snaps[2].gk_current == gk1)
    });
    assert_eq!(
        world.snaps[0].gk_current, gk1,
        "gateway GK advanced during the outage"
    );
    if group {
        assert_eq!(
            world.snaps[2].gk_current, gk0,
            "island B holds the old GK until the heal"
        );
    } else {
        assert_eq!(
            world.snaps[2].gk_current, gk1,
            "reachable B GK advanced during the outage"
        );
    }
    assert_eq!(
        world.snaps[1].gk_current, gk0,
        "isolated A holds the old GK"
    );
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "RRS+GK advanced, notice still unconfirmed: {notice:?}"
    );
    // The outage never counts as reached: solo leaves no reachable
    // member unapplied (A's erasure is not RRS distribution); the
    // group variant counts the legitimately unapplied B unknown.
    let progress = world
        .provision
        .site
        .link
        .operation(&outcome.operation_id)
        .expect("revoke status")
        .expect("revoke tracked");
    if group {
        assert!(
            progress.distribution.unknown >= 1,
            "island B counts unknown: {:?}",
            progress.distribution
        );
    } else {
        assert_eq!(
            progress.distribution.unknown, 0,
            "solo outage counts nothing unknown: {:?}",
            progress.distribution
        );
    }

    // Expire the 60 s direct-send window, then reconnect.
    for _ in 0..2600 {
        world.step(25);
    }
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "window expired, still unconfirmed: {notice:?}"
    );
    assert!(
        world.snaps[1].has_site,
        "isolated A still holds its site: {:?}",
        world.snaps[1]
    );
    if group {
        assert!(
            world.snaps[2].link_sessions > 0,
            "the in-group link is still up at the heal: {:?}",
            world.snaps[2]
        );
        world.switch.heal(0);
        // B enforces only now — and the live in-group link must not
        // block the recovery that follows.
        world.pump_until(12000, |snaps| snaps[2].rrs_applied > b_rrs);
        assert!(
            world.snaps[2].rrs_applied > b_rrs,
            "B enforced after the heal: {:?}",
            world.snaps[2]
        );
    } else {
        world.switch.heal(1);
    }
    let rs_epoch = world
        .provision
        .site
        .link
        .operation(&outcome.operation_id)
        .expect("revoke status")
        .expect("revoke tracked")
        .rs_epoch;
    assert_eq!(
        world.snaps[2].applied_rs, rs_epoch,
        "B enforces the RRS that revokes A"
    );

    // Refusal after the heal: A's retries (direct and relayed) never
    // deliver and admit no session; B's RRS epoch above is the
    // reason, not a mere RX hush. Re-convergence is still in flight
    // when the enforcement lands — B (not revoked) re-links to the
    // gateway and that bumps the same counters. Baseline only once
    // they have settled, so the window measures revoked-A admissions
    // alone.
    let mut last_gw = u32::MAX;
    let mut last_b = u32::MAX;
    let mut quiet = 0u32;
    for _ in 0..20000 {
        world.step(25);
        let gw = world.snaps[0].link_established + world.snaps[0].end_established;
        let b = world.snaps[2].link_established + world.snaps[2].end_established;
        if gw == last_gw && b == last_b {
            quiet += 1;
            if quiet >= 200 {
                break;
            }
        } else {
            quiet = 0;
            last_gw = gw;
            last_b = b;
        }
    }
    let b_rx = world.snaps[2].rx_count;
    let gw_est = world.snaps[0].link_established + world.snaps[0].end_established;
    let b_est = world.snaps[2].link_established + world.snaps[2].end_established;
    let delivered_pre = world.snaps[1]
        .app_tx
        .iter()
        .filter(|tx| tx.state == DELIVERY_DELIVERED)
        .count();
    for round in 0..3 {
        let dst = if round % 2 == 0 {
            NODE_B
        } else {
            testkit::GATEWAY
        };
        world.peers[1].app_send(dst, b"r2-revoked-data");
        for _ in 0..40 {
            world.step(25);
        }
        let delivered_now = world.snaps[1]
            .app_tx
            .iter()
            .filter(|tx| tx.state == DELIVERY_DELIVERED)
            .count();
        assert_eq!(
            delivered_now, delivered_pre,
            "round {round}: no revoked A send delivered: {:?}",
            world.snaps[1].app_tx
        );
    }
    assert_eq!(
        world.snaps[2].rx_count, b_rx,
        "B took no app RX from revoked A"
    );
    assert_eq!(
        world.snaps[0].link_established + world.snaps[0].end_established,
        gw_est,
        "gateway admitted no new session from A"
    );
    assert_eq!(
        world.snaps[2].link_established + world.snaps[2].end_established,
        b_est,
        "relay admitted no new session from A"
    );

    revoked_a_to_holdoff(&mut world, tag, id_fp_before);
}

#[test]
fn mesh_r2_isolated_revoke_and_recovery() {
    // Solo: only A isolated; the survivors enforce during the outage.
    r2_once("r2-solo", false);
    // Group: B/A isolated from G as one island; in-group traffic
    // survives the revoke until the heal.
    r2_once("r2-group", true);
}

/// A manual GK rotation through the service on the virtual clock
/// (not the API socket's process clock — see K1). Returns the new
/// epoch on commit, or the rejection code when BUSY/CONFLICT.
fn rotate_direct(world: &mut MeshWorld, expected: u32, key: &str) -> Result<u32, String> {
    let now = world.now;
    let outcome = world
        .provision
        .site
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
    match outcome {
        Ok(json) => {
            let value: routeloom_json::Json = routeloom_json::parse(&json).expect("outcome parses");
            assert_eq!(
                value.get("state").and_then(|v| v.as_str()),
                Some("committed")
            );
            Ok(value.get("to").and_then(|v| v.as_u64()).expect("to epoch") as u32)
        }
        Err(error) => Err(error.code.to_string()),
    }
}

/// Stages a site-epoch cutover through the service on the virtual
/// clock (not the API socket's process clock — the 600 s prepare
/// window would lapse instantly otherwise; same harness-only mixup
/// the GK rotations work around). Returns the operation id.
fn stage_cutover(world: &mut MeshWorld, key: &str) -> String {
    use routeloom_provision::signer::FileRootSigner;
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
    let outcome_json = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover(
                501,
                super::cutover::CutoverRequest {
                    expected_site_epoch: testkit::SITE_EPOCH,
                    next_site_cert: next_cert.clone(),
                    key: key.into(),
                },
                HostTime::sync(world.now),
            )
        })
        .0
        .expect("cutover stages");
    let outcome_value: routeloom_json::Json =
        routeloom_json::parse(&outcome_json).expect("outcome parses");
    assert_eq!(
        outcome_value.get("state").and_then(|v| v.as_str()),
        Some("preparing")
    );
    outcome_value
        .get("operation_id")
        .and_then(|v| v.as_str())
        .expect("operation id")
        .to_string()
}

/// K1 (§5.2): A misses two consecutive GK epochs on forced G—B—A
/// while G/B advance to g+1 then g+2 and the old-key RX overlap
/// expires. A is never counted applied; its stale-keyed chatter is
/// refused on the generation (which never reaches tag verification,
/// so this is key rejection, not replay); then A converges straight
/// to g+2 (no g+1 redistribution) and current-key traffic flows. The
/// durable-ACK→stable tail is covered by citation (see the end).
#[test]
fn mesh_k1_gk_double_miss() {
    use routeloom_client::site::SiteAdmin;
    let Some(mut world) = MeshWorld::start("k1", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "k1 rotate");
    let gk0 = world.active_gk();
    // Pre-rotation control: unicast delivers at g0.
    world.peers[1].app_send(NODE_B, b"k1-before");
    world.pump_until(3000, |snaps| {
        snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "pre-rotation A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    // A misses two rotations outright. Both rotate through the service
    // with the virtual clock: the API socket would stamp the process
    // monotonic clock while the harness ticks the authority on
    // wall-based virtual time, which wedges the 60 s cleanup gate
    // (same harness-only mixup the cutover test works around — the
    // production daemon runs one clock).
    world.switch.isolate(1);
    let gk1 = rotate_direct(&mut world, gk0, "k1-gk-1").expect("rotate 1 commits");
    assert!(gk1 > gk0);
    world.pump_until(8000, |snaps| {
        snaps[0].gk_current == gk1 && snaps[2].gk_current == gk1
    });
    assert_eq!(world.snaps[0].gk_current, gk1, "gateway at g+1");
    assert_eq!(world.snaps[2].gk_current, gk1, "B at g+1");
    assert_eq!(world.snaps[1].gk_current, gk0, "A missed g+1");
    // The authority activates g+1 late (A's stage deadline runs while
    // it is dark) and only then starts the 60 s post-activation
    // cleanup that BUSYs a successor — wait for the activation first.
    for _ in 0..4000 {
        world.step(25);
        let active = world
            .provision
            .site
            .link
            .group_key_status()
            .map(|s| s.active)
            .unwrap_or(0);
        if active == gk1 {
            break;
        }
    }
    assert_eq!(
        world
            .provision
            .site
            .link
            .group_key_status()
            .expect("gk status")
            .active,
        gk1,
        "authority activated g+1"
    );
    // A successor is allowed while catching_up (§6.3): G/B move on
    // to g+2 with A still dark. Retry past the cleanup window.
    let mut gk2 = None;
    for _ in 0..70 {
        match rotate_direct(&mut world, gk1, "k1-gk-2") {
            Ok(to) => {
                gk2 = Some(to);
                break;
            }
            Err(_) => {
                for _ in 0..40 {
                    world.step(25);
                }
            }
        }
    }
    let gk2 = gk2.expect("rotate 2 commits past cleanup");
    assert!(gk2 > gk1);
    world.pump_until(8000, |snaps| {
        snaps[0].gk_current == gk2 && snaps[2].gk_current == gk2
    });
    assert_eq!(world.snaps[0].gk_current, gk2, "gateway at g+2");
    assert_eq!(world.snaps[2].gk_current, gk2, "B at g+2");
    assert_eq!(world.snaps[1].gk_current, gk0, "A missed g+2");
    let status = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status");
    assert_eq!(status.active, gk2);
    assert!(
        status.unknown >= 1,
        "A is not counted g+2-applied: {status:?}"
    );
    // Past the old-key RX overlap (Manual: 60 s from the g+2
    // activation the pump just observed) before A may speak again.
    for _ in 0..2800 {
        world.step(25);
    }
    assert_eq!(
        world.snaps[1].gk_current, gk0,
        "A still holds g0 past the overlap"
    );

    // Stale-key rejection in the first breath after the heal: A's
    // links are down so it re-discovers immediately, still keyed g0,
    // while its own rescue (channel re-handshake, then Pull/ZT) needs
    // far longer. Arrival plus the generation verdict plus no
    // admission is the complete evidence: an unknown generation never
    // reaches tag verification — a replay verdict would need an
    // accepted generation first — so growth here is key rejection,
    // not replay. The trailing gk check voids the window loudly if A
    // ever converges too fast to judge.
    world.switch.heal(1);
    let b_raw = world.snaps[2].scope_raw_rx;
    let b_unkgen = world.snaps[2].scope_unknown_generation;
    let b_scope_ok = world.snaps[2].scope_accepted;
    for _ in 0..150 {
        world.step(25);
    }
    assert!(
        world.snaps[2].scope_raw_rx > b_raw,
        "A's stale chatter arrived: {:?}",
        world.snaps[2]
    );
    assert!(
        world.snaps[2].scope_unknown_generation > b_unkgen,
        "B rejects it as an unknown generation: {:?}",
        world.snaps[2]
    );
    assert_eq!(
        world.snaps[2].scope_accepted, b_scope_ok,
        "B admitted none of it: {:?}",
        world.snaps[2]
    );
    assert_eq!(
        world.snaps[1].gk_current, gk0,
        "A still stale at the verdict: {:?}",
        world.snaps[1]
    );

    // Full convergence, straight to g+2 — Pull or ZT, but never
    // through the dead g+1 (no redistribution of it exists to take).
    // Every step is sampled: any staging of the dead epoch fails.
    let mut saw_gk1 = false;
    for _ in 0..12000 {
        world.step(25);
        let held = world.snaps[1].gk_current;
        saw_gk1 |= held == gk1;
        if held == gk2 {
            break;
        }
    }
    assert_eq!(
        world.snaps[1].gk_current, gk2,
        "A converged to g+2: {:?}",
        world.snaps[1]
    );
    assert!(!saw_gk1, "A never staged the dead g+1");
    // A fresh boot starts a discovery round with the durable g+2 key;
    // mere radio isolation can leave its existing link idle throughout
    // this observation window.
    world.peers[1].power_cut();
    world.pump_until(3000, |snaps| snaps[2].scope_accepted > b_scope_ok);
    assert!(
        world.snaps[2].scope_accepted > b_scope_ok,
        "same-key scope flows again at g+2: {:?}",
        world.snaps[2]
    );
    // Tail coverage ("durable ACK clears unknown → stable", plus a
    // post-outage unicast) lives in mesh_group_key_rotate_acknowledged:
    // after this outage A's transit channel cannot come back (long
    // clean isolation wedges link/route re-establishment —
    // out-of-scope routing liveness gap, residual R-D04-K1a — so its
    // rotation ACKs never flow), and past ~9 min virtual the
    // gateway's quiet-probe Pull trips a pull-loss resend that
    // exhausts back to Unknown (residual R-D04-K1b, host GK). Neither
    // is D04's to fix here.
}

/// C1 (§5.2): healthy adoption from the leaves. Everyone holds the
/// latest PREPARED, then COMMITs dispatch leaf-first along the route
/// tree: no parent's COMMIT is sent (or adopted) before its child's
/// COMMIT_STORED verifies, parents still advance while APPLIED is 0,
/// and the run ends 3/0/0 with one adoption reboot each, a fresh USB
/// session, and bidirectional new-network delivery. `leaf`/`relay`
/// are peer indices; the direct gateway—leaf legs must stay silent.
fn c1_once(tag: &str, switch: Switch, gate: usize, leaf: usize, relay: usize) {
    use routeloom_client::site::SiteAdmin;
    let nodes = [testkit::GATEWAY, NODE_A, NODE_B];
    let Some(mut world) = MeshWorld::start(tag, switch) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, gate, "c1 cutover");
    // Pre-cutover delivery works end to end (leaf to gateway).
    world.peers[leaf].app_send(testkit::GATEWAY, b"c1-before");
    world.pump_until(3000, |snaps| {
        snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "pre-cutover leaf->gateway delivered: {:?}",
        world.snaps[leaf].app_tx
    );

    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, tag);
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }
    // Everyone holds the latest PREPARED: same revision everywhere.
    // (The host-side ACKs lag the peer phases by a relay+USB beat.)
    for _ in 0..1000 {
        let targets = world.cutover_targets(&operation_id);
        if targets.len() == 3 && targets.iter().all(|t| t.1 == "prepared") {
            break;
        }
        world.step(25);
    }
    let targets = world.cutover_targets(&operation_id);
    assert_eq!(targets.len(), 3, "three targets: {targets:?}");
    assert!(
        targets.iter().all(|t| t.1 == "prepared"),
        "all prepared: {targets:?}"
    );
    assert_eq!(targets[0].2, targets[1].2, "same revision: {targets:?}");
    assert_eq!(targets[1].2, targets[2].2, "same revision: {targets:?}");

    // Fast-forward to just before the window end, then sample the
    // COMMIT dispatch at full resolution: send ticks (a target
    // leaving Prepared post-commit), stored ticks (verified
    // COMMIT_STORED), and the applied count at each parent send.
    // The last 70 s run at 100 ms: the RouteState query round trip
    // (down, relay, answer, forward, up) needs several TX
    // opportunities inside its 4 s routed lifetime, and 1 s steps
    // starve the relay queue behind routine chatter — the tree would
    // stay unknown and leaf-first would never gate.
    let window_end = staged_at + super::cutover::CUTOVER_PREPARE_WINDOW_MS;
    while world.now + 70_000 < window_end {
        world.step(1000);
    }
    while world.now + 10_000 < window_end {
        world.step(100);
    }
    let mut send_tick = [None::<u64>; 3];
    let mut stored_tick = [None::<u64>; 3];
    let mut applied_at_send = [None::<u64>; 3];
    let mut phase_at_send = [PHASE_PREPARED; 3];
    for _ in 0..12000 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase == "preparing" || phase == "waiting_gateway" {
            continue;
        }
        let progress = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .expect("cutover tracked");
        let targets = world.cutover_targets(&operation_id);
        for (index, node) in nodes.iter().enumerate() {
            // COMMIT dispatch is attempts-observed: sends never move
            // GrantState (only receipts do), and attempts restart at
            // zero on commit — the first post-commit attempt is the
            // dispatch tick the tree order governs.
            let dispatched = targets
                .iter()
                .find(|t| t.0 == *node)
                .map(|t| t.3 > 0)
                .unwrap_or(false);
            if send_tick[index].is_none() && dispatched {
                send_tick[index] = Some(world.now);
                applied_at_send[index] = Some(progress.applied);
                phase_at_send[index] = world.snaps[index].phase;
            }
            if stored_tick[index].is_none() {
                let stored = world
                    .cutover_route(&operation_id, *node)
                    .map(|plan| plan.stored)
                    .unwrap_or(false);
                if stored {
                    stored_tick[index] = Some(world.now);
                }
            }
        }
        let done = world.snaps.iter().all(|s| s.phase == PHASE_ACTIVE) && progress.applied == 3;
        // The root's stored gates nothing (nobody waits for it), so
        // only the gated children must show receipts.
        if done
            && send_tick.iter().all(|t| t.is_some())
            && stored_tick[leaf].is_some()
            && stored_tick[relay].is_some()
        {
            break;
        }
    }
    // The leaf's COMMIT is sent and verified before the relay's is
    // sent; the relay's before the gateway's. Neither parent adopts
    // (leaves Prepared) before its child's receipt verifies, and both
    // parents advance while APPLIED is still 0.
    assert!(
        send_tick.iter().all(Option::is_some),
        "every target sent: send={send_tick:?} stored={stored_tick:?} targets={:?} routes={:?}",
        world.cutover_targets(&operation_id),
        nodes.map(|node| world.cutover_route(&operation_id, node))
    );
    let send = send_tick.map(Option::unwrap);
    let stored_leaf = stored_tick[leaf].expect("leaf stored");
    let stored_relay = stored_tick[relay].expect("relay stored");
    let stored = [stored_tick[0], stored_tick[1], stored_tick[2]];
    assert!(
        send[leaf] < stored_leaf,
        "leaf sent before its stored verifies: send={send:?} stored={stored:?}"
    );
    // Cross-target gates admit the same tick: the host verifies a
    // STORED and releases the parent in one tick (receipts drain before
    // dispatch), which is causally after, not simultaneous.
    assert!(
        stored_leaf <= send[relay],
        "relay waits for the leaf receipt: send={send:?} stored={stored:?}"
    );
    assert!(
        stored_relay <= send[0],
        "gateway waits for the relay receipt: send={send:?} stored={stored:?}"
    );
    assert!(
        applied_at_send[relay] == Some(0),
        "relay advances while APPLIED is 0: {applied_at_send:?}"
    );
    assert!(
        applied_at_send[0] == Some(0),
        "gateway advances while APPLIED is 0: {applied_at_send:?}"
    );
    assert_eq!(
        phase_at_send[relay], PHASE_PREPARED,
        "relay still prepared at its send (adopts after)"
    );
    assert_eq!(
        phase_at_send[0], PHASE_PREPARED,
        "gateway still prepared at its send (adopts after)"
    );

    // Adoption converges on the new network/GK with re-opened
    // channels and all APPLIEDs landed.
    let (next_gk, new_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = super::records::parse_op_token(&operation_id).unwrap();
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.new_network)
        })
        .0;
    for _ in 0..8000 {
        world.step(25);
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done {
            let applied = world
                .provision
                .site
                .link
                .cutover_operation(&operation_id)
                .unwrap()
                .map(|p| p.applied)
                .unwrap_or(0);
            if applied == 3 {
                break;
            }
        }
    }
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(snap.authority_ready, "peer {index} channel re-open");
    }
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    assert!(
        !progress.recovery_pending,
        "no straggler parked: {progress:?}"
    );
    assert_eq!(progress.applied, 3, "APPLIED=3: {progress:?}");
    assert_eq!(progress.recovered, 0, "recovered=0: {progress:?}");
    assert_eq!(progress.unknown, 0, "unknown=0: {progress:?}");
    assert_eq!(
        [
            world.peers[0].reboots,
            world.peers[1].reboots,
            world.peers[2].reboots
        ],
        [1, 1, 1],
        "one adoption reboot each"
    );
    assert_eq!(
        world.usb_auth_total(),
        2,
        "gateway USB re-authenticated after its reboot"
    );

    // Bidirectional new-network delivery, gateway to leaf and back.
    let payload = b"c1-down";
    world.peers[0].app_send(nodes[leaf], payload);
    let leaf_rx = world.snaps[leaf].rx_count;
    world.pump_until(3000, |snaps| snaps[leaf].rx_count > leaf_rx);
    assert!(
        world.snaps[leaf].rx_count > leaf_rx,
        "gateway->leaf delivered: {:?}",
        world.snaps[leaf]
    );
    assert_eq!(&world.snaps[leaf].rx[..payload.len()], payload);
    let payload = b"c1-upxx";
    world.peers[leaf].app_send(testkit::GATEWAY, payload);
    world.pump_until(3000, |snaps| {
        snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "leaf->gateway delivered: {:?}",
        world.snaps[leaf].app_tx
    );

    // The direct gateway—leaf path stayed silent: everything the leaf
    // got came down the tree through the relay.
    assert_eq!(
        world.switch.leg_delivered[0][leaf], 0,
        "no direct gateway->leaf frame"
    );
    assert_eq!(
        world.switch.leg_delivered[leaf][0], 0,
        "no direct leaf->gateway frame"
    );
}

#[test]
fn mesh_c1_tree_ordered_adoption() {
    // Forward: G—B—A, where the tree order (A first) coincides with
    // the NodeId order — the scheduler must use the tree anyway.
    c1_once("c1-fwd", Switch::forced_multihop(), 1, 1, 2);
    // Reversed: G—A—B, where the tree order (B first) runs against
    // the NodeId order under the same conditions.
    let mut reversed = Switch::direct();
    reversed.set_audible(0, 2, false);
    reversed.set_audible(2, 0, false);
    c1_once("c1-rev", reversed, 2, 2, 1);
}

/// KGuard-visible join requests currently open for one node (C2: the
/// ZT auto-reissue must not open any — "人手 allow 操作は 0" is the
/// absence of new requests, not a served decision).
fn kguard_requests_for(world: &MeshWorld, node: u64) -> usize {
    world
        .provision
        .site
        .service
        .with(|a| a.requests.values().filter(|r| r.facts.node == node).count())
        .0
}

/// C2 (§5.2): the leaf misses the whole COMMIT while everyone else
/// adopts. `island` selects the variant: only A's downstream dies
/// (G and B switch inside the deadline, A stays Prepared-unknown),
/// or G is cut from the B/A island (G adopts alone, the island
/// keeps old-network mutual comms, both stay unknown). Past the
/// grace the fault clears and the stragglers must come back through
/// the ZT auto-reissue — Recovered, never Applied, with no KGuard
/// request opened for them.
fn c2_once(tag: &str, island: bool) {
    use routeloom_client::site::SiteAdmin;
    let Some(mut world) = MeshWorld::start(tag, Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "c2 cutover");
    let kguard_a_before = kguard_requests_for(&world, NODE_A);
    let kguard_b_before = kguard_requests_for(&world, NODE_B);

    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, tag);
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }
    // The peers' PREPARE receipts are still in flight when they stage:
    // drain them at 25 ms until the Owner has seen every target's
    // receipt before fast-forwarding. A queued carrier debits its
    // routed TTL while it waits, and a 1 s step ages it past the
    // receiver's dead-on-arrival gate — the same harness artifact as
    // the commit legs below.
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }
    let (next_gk, new_network, old_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = super::records::parse_op_token(&operation_id).unwrap();
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

    // Fast-forward to the commit, then run the grace at full
    // resolution (same pacing as C1: the tree traffic needs it).
    // The stable window fast-forwards in 1 s steps ONLY while the
    // air is silent: a 1 s step stamps a full second of RX age on
    // every delivered frame, and one that also carries send-queue
    // delay dies on the receiver's dead-on-arrival gate. Busy air
    // ticks at 25 ms.
    let window_end = staged_at + super::cutover::CUTOVER_PREPARE_WINDOW_MS;
    let mut quiet_ms = 0u64;
    while world.now + 10_000 < window_end {
        let delivered_before = world.switch.delivered;
        let jump = quiet_ms >= 3_000;
        world.step(if jump { 1_000 } else { 25 });
        quiet_ms = if world.switch.delivered == delivered_before {
            quiet_ms.saturating_add(if jump { 1_000 } else { 25 })
        } else {
            0
        };
    }
    for _ in 0..4000 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase == "committed" {
            break;
        }
    }
    let t0 = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover_grace_until_mono
                .saturating_sub(super::cutover::CUTOVER_GRACE_MS)
        })
        .0;
    assert!(
        t0 > staged_at,
        "durable COMMIT passed with a live grace: t0={t0} staged={staged_at}"
    );
    if island {
        // G—[B/A island] cut for the whole grace. The island keeps
        // old-Prepared-group mutual comms while G commits alone.
        world.switch.isolate(0);
        world.peers[1].app_send(NODE_B, b"c2-island");
        world.pump_until(3000, |snaps| {
            snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
        });
        assert!(
            world.snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED),
            "island A->B delivers while Prepared: {:?}",
            world.snaps[1].app_tx
        );
    } else {
        // A's whole COMMIT dies downstream of the relay for the
        // grace: unicast only (broadcasts still cross, so discovery
        // survives — the fault is the transfer, not the radio).
        world.switch.drop_next[2][1] += 500;
    }
    // Run past D; the reachable side must have switched by then.
    let (want_applied, want_recovered) = if island { (1, 2) } else { (2, 1) };
    for _ in 0..4000 {
        world.step(25);
        if world.now < t0 + super::cutover::CUTOVER_GRACE_MS + 5_000 {
            continue;
        }
        let applied = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.applied)
            .unwrap_or(0);
        if applied == want_applied {
            break;
        }
    }
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    assert!(
        world.now >= t0 + super::cutover::CUTOVER_GRACE_MS,
        "past the grace: now={} t0={t0}",
        world.now
    );
    // The reachable side switched inside the deadline; the
    // stragglers sit Prepared-unknown (never silently dropped).
    assert_eq!(
        world.snaps[0].phase, PHASE_ACTIVE,
        "gateway adopted: {:?}",
        world.snaps[0]
    );
    assert_eq!(
        world.snaps[0].adopted_network, new_network,
        "gateway on the new network: {:?}",
        world.snaps[0]
    );
    assert_eq!(
        world.snaps[1].phase, PHASE_PREPARED,
        "A still Prepared: {:?}",
        world.snaps[1]
    );
    assert_eq!(
        world.snaps[1].adopted_network, old_network,
        "A still on the old network: {:?}",
        world.snaps[1]
    );
    if island {
        assert_eq!(
            world.snaps[2].phase, PHASE_PREPARED,
            "island B still Prepared: {:?}",
            world.snaps[2]
        );
    } else {
        assert_eq!(
            world.snaps[2].phase, PHASE_ACTIVE,
            "relay B adopted: {:?}",
            world.snaps[2]
        );
        assert_eq!(
            world.snaps[2].adopted_network, new_network,
            "relay B on the new network: {:?}",
            world.snaps[2]
        );
        assert!(
            world.switch.leg_dropped[2][1] > 0,
            "the downstream fault actually ate A's COMMIT"
        );
    }
    assert_eq!(progress.applied, want_applied, "applied: {progress:?}");
    assert_eq!(progress.recovered, 0, "nothing recovered yet: {progress:?}");
    assert_eq!(
        progress.unknown, want_recovered,
        "stragglers unknown: {progress:?}"
    );
    assert!(progress.recovery_pending, "recovery pending: {progress:?}");
    let targets = world.cutover_targets(&operation_id);
    let state_of = |node: u64| {
        targets
            .iter()
            .find(|t| t.0 == node)
            .map(|t| t.1.clone())
            .unwrap_or_default()
    };
    let attempts_of = |node: u64| {
        targets
            .iter()
            .find(|t| t.0 == node)
            .map(|t| t.3)
            .unwrap_or(0)
    };
    // Post-commit Prepared counts as unknown (not silently ready):
    // the row still says prepared while the split says unknown.
    assert_eq!(state_of(NODE_A), "prepared", "A row: {targets:?}");
    assert!(
        attempts_of(NODE_A) > 0,
        "A's COMMIT was dispatched (and missed): {targets:?}"
    );
    assert!(
        world
            .cutover_route(&operation_id, NODE_A)
            .is_some_and(|plan| plan.deferred),
        "A cut by its layer deadline"
    );
    if island {
        assert_eq!(state_of(NODE_B), "prepared", "B row: {targets:?}");
        assert!(
            world
                .cutover_route(&operation_id, NODE_B)
                .is_some_and(|plan| plan.deferred),
            "island B cut by its layer deadline"
        );
    }

    // The fault clears; Prepared must not wedge — the stragglers
    // come back through the ZT auto-reissue (no KGuard round trip).
    world.switch.drop_next = [[0; 3]; 3];
    world.switch.ack_drop_next = [[0; 3]; 3];
    if island {
        world.switch.heal(0);
    }
    let mut chatter_rounds = 0_u32;
    // The island serializes the stragglers: each can only ZT-verify
    // through the other while it is not itself in ZeroTouch, so one may
    // burn a full abandon (300 s) plus cooldown (600 s) before retrying.
    for i in 0..90000 {
        world.step(25);
        let progress = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .expect("cutover tracked");
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done && progress.unknown == 0 && progress.recovered == want_recovered {
            break;
        }
        // Survivor chatter carries the newer-generation evidence a
        // dark Prepared straggler strikes on (04 §3.5, like R1).
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            world.peers[2].app_send(testkit::GATEWAY, b"c2-chatter");
            world.peers[0].app_send(NODE_B, b"c2-chatter");
        }
    }
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(snap.authority_ready, "peer {index} channel re-open");
    }
    // The straggler never held the COMMIT, so applied cannot move —
    // the reissue lands it in recovered instead.
    assert_eq!(
        progress.applied, want_applied,
        "applied never counts the straggler: {progress:?}"
    );
    assert_eq!(
        progress.recovered, want_recovered,
        "stragglers recovered: {progress:?}"
    );
    assert_eq!(progress.unknown, 0, "unknown drained: {progress:?}");
    assert!(!progress.recovery_pending, "converged: {progress:?}");
    let targets = world.cutover_targets(&operation_id);
    assert_eq!(
        targets.iter().find(|t| t.0 == NODE_A).map(|t| t.1.as_str()),
        Some("recovered"),
        "A recovered: {targets:?}"
    );
    assert_eq!(
        kguard_requests_for(&world, NODE_A),
        kguard_a_before,
        "no KGuard request for A (auto-reissue)"
    );
    if island {
        assert_eq!(
            targets.iter().find(|t| t.0 == NODE_B).map(|t| t.1.as_str()),
            Some("recovered"),
            "island B recovered: {targets:?}"
        );
        assert_eq!(
            kguard_requests_for(&world, NODE_B),
            kguard_b_before,
            "no KGuard request for island B (auto-reissue)"
        );
    }
    assert_eq!(
        [world.peers[0].reboots, world.peers[2].reboots],
        [1, 1],
        "gateway and relay took one adoption reboot each"
    );

    // Bidirectional new-network delivery, gateway to leaf and back.
    let payload = b"c2-down";
    world.peers[0].app_send(NODE_A, payload);
    let leaf_rx = world.snaps[1].rx_count;
    world.pump_until(3000, |snaps| snaps[1].rx_count > leaf_rx);
    assert!(
        world.snaps[1].rx_count > leaf_rx,
        "gateway->leaf delivered: {:?}",
        world.snaps[1]
    );
    assert_eq!(&world.snaps[1].rx[..payload.len()], payload);
    world.peers[1].app_send(testkit::GATEWAY, b"c2-upxxx");
    world.pump_until(3000, |snaps| {
        snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "leaf->gateway delivered: {:?}",
        world.snaps[1].app_tx
    );
}

#[test]
fn mesh_c2_commit_miss_and_reissue() {
    // Only the leaf's downstream dies: G and B switch inside the
    // deadline, A recovers through the reissue.
    c2_once("c2-miss", false);
    // G cut from the B/A island: G adopts alone, the island keeps
    // old-network comms, both stragglers recover.
    c2_once("c2-island", true);
}

/// Shared C3–C7 drive: converge, stage the cutover, drain every
/// PREPARED receipt at 25 ms, fast-forward the prepare window on
/// quiet air, then run until the authority durably commits and the
/// grace opens. Returns (operation, next_gk, new_network,
/// old_network, grace_start).
fn cutover_through_commit(world: &mut MeshWorld, tag: &str) -> (String, u32, u64, u64, u64) {
    converge_gated(world, 1, "c3-c7 cutover");
    let staged_at = world.now;
    let operation_id = stage_cutover(world, tag);
    cutover_finish_prepare(world, operation_id, staged_at)
}

fn cutover_finish_prepare(
    world: &mut MeshWorld,
    operation_id: String,
    staged_at: u64,
) -> (String, u32, u64, u64, u64) {
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }
    // Peer-local PREPARED is not host evidence: drain the in-flight
    // receipts at 25 ms before any fast-forward, or a queued carrier
    // debits its routed TTL in a 1 s step and dies dead-on-arrival.
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }
    let (next_gk, new_network, old_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = super::records::parse_op_token(&operation_id).unwrap();
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
    let window_end = staged_at + super::cutover::CUTOVER_PREPARE_WINDOW_MS;
    let mut quiet_ms = 0u64;
    while world.now + 10_000 < window_end {
        let delivered_before = world.switch.delivered;
        // RouteState queries start in the last minute. Keep their
        // carrier hops at the normal 25 ms radio cadence.
        let jump = quiet_ms >= 3_000
            && world.now < window_end.saturating_sub(super::cutover::CUTOVER_ROUTE_QUERY_WINDOW_MS);
        world.step(if jump { 1_000 } else { 25 });
        quiet_ms = if world.switch.delivered == delivered_before {
            quiet_ms.saturating_add(if jump { 1_000 } else { 25 })
        } else {
            0
        };
    }
    for _ in 0..4000 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase == "committed" {
            break;
        }
    }
    let t0 = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover_grace_until_mono
                .saturating_sub(super::cutover::CUTOVER_GRACE_MS)
        })
        .0;
    assert!(
        t0 > staged_at,
        "durable COMMIT passed with a live grace: t0={t0} staged={staged_at}"
    );
    (operation_id, next_gk, new_network, old_network, t0)
}

/// C3–C7 progress snapshot for the running cutover op.
fn cutover_progress(
    world: &MeshWorld,
    operation_id: &str,
) -> routeloom_client::site::CutoverProgress {
    world
        .provision
        .site
        .link
        .cutover_operation(operation_id)
        .unwrap()
        .expect("cutover tracked")
}

/// Run to the recovery verdict: every peer ACTIVE on the new
/// network/GK with its authority channel re-open, the ledger's
/// unknown drained, and no KGuard request for any straggler
/// (auto-reissue, not a manual round trip). `chatter` drives the
/// survivor evidence a dark straggler strikes on (04 §3.5).
fn cutover_converged(
    world: &mut MeshWorld,
    operation_id: &str,
    new_network: u64,
    next_gk: u32,
    want_recovered: Option<u64>,
) {
    let mut chatter_rounds = 0_u32;
    for i in 0..48000 {
        world.step(25);
        let progress = cutover_progress(world, operation_id);
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done
            && progress.unknown == 0
            && want_recovered.map_or(true, |w| progress.recovered == w)
        {
            break;
        }
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            world.peers[2].app_send(testkit::GATEWAY, b"c3-c7-chatter");
            world.peers[0].app_send(NODE_B, b"c3-c7-chatter");
        }
    }
    let progress = cutover_progress(world, operation_id);
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(
            snap.authority_ready,
            "peer {index} channel re-open: {:?}",
            world.snaps
        );
    }
    assert_eq!(progress.unknown, 0, "unknown drained: {progress:?}");
    if let Some(want) = want_recovered {
        assert_eq!(progress.recovered, want, "recovered: {progress:?}");
    }
    assert!(!progress.recovery_pending, "converged: {progress:?}");
}

/// C3: the member's APPLIED receipt dies in flight while the member
/// itself commits and adopts on time. A lost receipt copy is not a
/// lost adoption: the site can never count A applied on the evidence
/// it does not hold, so A's row goes unknown at the grace boundary —
/// while the member's own receipt is journal-durable and keeps
/// retrying. When the uplink heals the real receipt lands and the
/// row resolves applied; the op never wedges and no KGuard round
/// trip is needed.
#[test]
fn mesh_c3_commit_applied_receipt_loss() {
    let Some(mut world) = MeshWorld::start("c3", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    let kguard_a_before = kguard_requests_for(&world, NODE_A);
    let (operation_id, next_gk, new_network, _old_network, t0) =
        cutover_through_commit(&mut world, "c3");
    // A's COMMIT comes down B→A while its APPLIED receipt goes back
    // up A→B. The uplink can only be cut after the commit lands —
    // the endpoint's inbound manifest refuses while a wedged
    // outbound holds it, so a premature cut kills the commit too.
    // The observable seam is A's adoption reboot: adopted_network
    // flips before the channel re-opens and the receipt goes out.
    // Arm the uplink drop then and hold it through the whole grace —
    // the receipt is production-persistent inside the window.
    world.pump_until(15000, |snaps| snaps[1].adopted_network == new_network);
    assert_eq!(
        world.snaps[1].adopted_network, new_network,
        "A adopted the new network on time: {:?}",
        world.snaps[1]
    );
    assert_eq!(world.peers[1].reboots, 1, "A took its adoption reboot");
    world.switch.drop_next[1][2] += 100_000;
    // Run out the grace with the uplink dark.
    while world.now < t0 + super::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(100);
    }
    assert!(
        world.switch.leg_dropped[1][2] > 0,
        "the uplink fault actually ate A's receipt traffic"
    );
    // At the boundary the site holds no receipt for A, so A's row
    // can never read applied — the ledger classifies from evidence,
    // not absence of fault (the row may still lag at prepared).
    let progress = cutover_progress(&world, &operation_id);
    let targets = world.cutover_targets(&operation_id);
    assert_ne!(
        targets.iter().find(|t| t.0 == NODE_A).map(|t| t.1.as_str()),
        Some("applied"),
        "A unaccounted while its receipts die in flight: {targets:?}"
    );
    assert!(
        progress.applied < 3,
        "no applied without a landed receipt: {progress:?}"
    );
    // Heal: the journal-durable receipt retry lands and reclassifies
    // A applied — late real evidence is still real evidence.
    world.switch.drop_next[1][2] = 0;
    cutover_converged(&mut world, &operation_id, new_network, next_gk, Some(0));
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied, 3, "A's receipt landed: {progress:?}");
    assert_eq!(
        kguard_requests_for(&world, NODE_A),
        kguard_a_before,
        "no KGuard request for A (auto-recovery)"
    );
}

#[test]
fn mesh_c3_stored_receipt_loss_and_power_cut() {
    let Some(mut world) = MeshWorld::start("c3-stored", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_through_commit(&mut world, "c3-stored");
    assert_eq!(
        world.snaps[1].adopted_network, old_network,
        "arm before A switches"
    );
    // A's COMMIT travels B→A. Cut power immediately after Switching
    // becomes durable, before the stored receipt can leave A.
    world.peers[1].cut_after_switching();
    for _ in 0..4000 {
        world.step(25);
        if world.peers[1].switching_cuts != 0 {
            break;
        }
    }
    assert_eq!(
        world.peers[1].switching_cuts, 1,
        "power cut after RLX1 Switching"
    );
    world.switch.drop_next[1][2] = 100_000;
    world.pump_until(4000, |snaps| snaps[1].adopted_network == new_network);
    assert!(
        !world
            .cutover_route(&operation_id, NODE_A)
            .is_some_and(|plan| plan.stored),
        "lost receipt is not stored evidence"
    );
    assert_eq!(
        world.snaps[1].adopted_network,
        new_network,
        "A resumed Switching: {:?}; targets={:?}",
        world.snaps[1],
        world.cutover_targets(&operation_id)
    );
    assert_ne!(world.snaps[1].adopted_network, old_network);
    while world.now < t0 + super::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(25);
    }
    assert!(world.switch.leg_dropped[1][2] > 0, "receipt leg was cut");
    let progress = cutover_progress(&world, &operation_id);
    assert!(
        progress.applied < 3,
        "lost receipt is not applied: {progress:?}"
    );
    assert!(progress.unknown > 0, "A remains unknown: {progress:?}");
    world.switch.drop_next[1][2] = 0;
    cutover_converged(&mut world, &operation_id, new_network, next_gk, Some(0));
    assert_eq!(cutover_progress(&world, &operation_id).applied, 3);
}

/// C4(a): reopen the whole daemon from SQLite while every member is
/// Prepared. The signed PREPARE and epoch allocation survive, while
/// the monotonic prepare window starts again in the new process.
#[test]
fn mesh_c4_daemon_restart_preparing() {
    let Some(mut world) = MeshWorld::start("c4-pre", Switch::forced_multihop()) else {
        return;
    };
    converge_gated(&mut world, 1, "c4 preparing");
    let operation_id = stage_cutover(&mut world, "c4-pre");
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for _ in 0..4000 {
        if world
            .cutover_targets(&operation_id)
            .iter()
            .all(|(_, s, _, _)| s == "prepared")
        {
            break;
        }
        world.step(25);
    }
    let op = super::records::parse_op_token(&operation_id).unwrap();
    let before = world
        .provision
        .site
        .service
        .with(|a| {
            let state = a.operations.get(&op).unwrap().cutover.as_ref().unwrap();
            (
                state.revision,
                state.next_gk_epoch,
                a.grant_bytes(op, NODE_A, super::revocation::OutboundKind::Prepare),
                a.store.load().unwrap().meta.get("next_serial").cloned(),
            )
        })
        .0;
    let restart_at = world.now;
    world.daemon_restart();
    world.step(25);
    let after = world
        .provision
        .site
        .service
        .with(|a| {
            let state = a.operations.get(&op).unwrap().cutover.as_ref().unwrap();
            (
                state.revision,
                state.next_gk_epoch,
                a.grant_bytes(op, NODE_A, super::revocation::OutboundKind::Prepare),
                a.store.load().unwrap().meta.get("next_serial").cloned(),
                state.started_mono_ms,
            )
        })
        .0;
    assert_eq!(before, (after.0, after.1, after.2, after.3));
    assert!(
        after.4 >= restart_at,
        "the prepare clock restarted: {} < {restart_at}",
        after.4
    );
    let (operation_id, next_gk, new_network, _old_network, t0) =
        cutover_finish_prepare(&mut world, operation_id, restart_at);
    assert!(t0 >= restart_at + super::cutover::CUTOVER_PREPARE_WINDOW_MS);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
}

/// C4(b): reopen after the COMMIT is durable with A still Prepared.
/// The new daemon has no old-context grace or queued sealed payloads;
/// the straggler recovers by reissue while committed peers stay new.
#[test]
fn mesh_c4_daemon_restart_committed() {
    let Some(mut world) = MeshWorld::start("c4-post", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, _t0) =
        cutover_through_commit(&mut world, "c4-post");
    assert_eq!(world.snaps[1].adopted_network, old_network);
    world.switch.drop_next[2][1] = 500;
    let old_usb = Arc::clone(&world.provision.usb);
    let old_join = Arc::clone(&world.join_adapter);
    world.daemon_restart();
    assert_ne!(
        old_usb.usb_incarnation(),
        world.provision.usb.usb_incarnation()
    );
    assert!(matches!(
        old_usb.handle_up(&[], world.now),
        Err(super::usb::AuthorityUpError::Closed)
    ));
    assert!(matches!(
        old_join.handle_up(&[], world.now),
        Err(super::usb::UpError::Closed)
    ));
    let (network, grace) = world
        .provision
        .site
        .service
        .with(|a| (a.network(), a.cutover_grace_until_mono))
        .0;
    assert_eq!(network, new_network);
    assert_eq!(grace, 0);
    let progress = cutover_progress(&world, &operation_id);
    assert!(
        progress.unknown > 0,
        "undelivered A stays unknown: {progress:?}"
    );
    world.switch.drop_next[2][1] = 0;
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
}

/// C5: the gateway↔host USB lane dies right after the durable
/// COMMIT so every dispatched COMMIT dies on the cable. The ledger
/// honestly flips the targets unknown (it never saw a receipt),
/// recovery_pending opens, and the members stay Prepared on the old
/// network. Reconnecting re-authenticates the authority session and
/// the member-driven recovery road converges every straggler — no
/// KGuard request, no silent applied.
#[test]
fn mesh_c5_gateway_disconnect_and_resume() {
    let Some(mut world) = MeshWorld::start("c5", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    let (operation_id, next_gk, new_network, _old_network, t0) =
        cutover_through_commit(&mut world, "c5");
    let old_usb = Arc::clone(&world.provision.usb);
    let old_join = Arc::clone(&world.join_adapter);
    let old_incarnation = old_usb.usb_incarnation();
    // The cable pull: nothing crosses the USB seam while it is down.
    // Member probes still cross the radio but the authority can't
    // answer — a Prepared straggler whose probes go unanswered must
    // eventually strike out and take the ZeroTouch reissue road.
    world.usb_disconnect();
    assert!(matches!(
        old_usb.handle_up(&[], world.now),
        Err(super::usb::AuthorityUpError::Closed)
    ));
    assert!(matches!(
        old_join.handle_up(&[], world.now),
        Err(super::usb::UpError::Closed)
    ));
    // Run past the grace on the dead lane — the old bindings the
    // COMMITs rode have expired out of the host's table, so no member
    // can be reached on them at all — then past the stragglers'
    // dead-silence bound (~120 s), so their own evidence has struck
    // them into the ZT reissue before the cable returns. The heal
    // must land inside their first refresh window (~5 min): an
    // abandoned refresh cools down for ten.
    let grace_end = t0 + super::cutover::CUTOVER_GRACE_MS;
    while world.now < grace_end + 130_000 {
        world.step(25);
    }
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(
        progress.applied, 0,
        "nothing could apply with the host lane down: {progress:?}"
    );
    assert!(
        progress.recovery_pending || progress.unknown > 0,
        "stragglers pending recovery: {progress:?}"
    );
    // Reconnect: the authority session re-authenticates (a fresh
    // session counts too — the physical rebind is its own evidence),
    // the refreshed members pull the ZT reissue, and the ledger
    // resolves honestly — a straggler that re-emits its durable
    // APPLIED receipt is applied, one proven through the recovery
    // road is recovered; only the split is timing.
    world.usb_reconnect();
    assert_ne!(world.provision.usb.usb_incarnation(), old_incarnation);
    assert_ne!(world.join_adapter.usb_incarnation(), old_incarnation);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(
        progress.applied + progress.recovered,
        3,
        "every target resolved after resume: {progress:?}"
    );
}

#[test]
fn mesh_c5_radio_partition_and_stale_usb_adapter() {
    use routeloom_protocol::host_ops::{
        encode_authority_down, encode_authority_up, AuthorityFragment,
    };
    let Some(mut world) = MeshWorld::start("c5-radio", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_through_commit(&mut world, "c5-radio");
    // The G—B leg fails while B/A still hold the old Prepared group.
    world.switch.isolate(0);
    let old_usb = Arc::clone(&world.provision.usb);
    let old_join = Arc::clone(&world.join_adapter);
    let delayed = AuthorityFragment {
        device: testkit::GATEWAY,
        transfer_id: 1,
        kind: CarrierKind::Envelope,
        hops: 0,
        total: 28,
        offset: 0,
        data: vec![0xA5; 28],
    };
    let delayed_up = encode_authority_up(&delayed).unwrap();
    let delayed_down = encode_authority_down(&delayed).unwrap();
    let sessions_before = world.usb_auth_total();
    // A gateway field reboot ends the old bridge session and binds
    // both host adapters to the fresh USB incarnation.
    let reboots_before = world.peers[0].reboots;
    world.peers[0].power_cut();
    world.step(25);
    assert!(world.peers[0].reboots > reboots_before);
    assert!(matches!(
        old_usb.handle_up(&delayed_up, world.now),
        Err(super::usb::AuthorityUpError::Closed)
    ));
    old_usb.requeue_front(vec![super::usb::AuthorityDown {
        bytes: delayed_down,
        device: testkit::GATEWAY,
        transfer_id: 1,
        admitted_ms: world.now,
    }]);
    assert!(old_usb.take_ready(world.now).is_empty());
    assert!(matches!(
        old_join.handle_up(&[], world.now),
        Err(super::usb::UpError::Closed)
    ));
    while world.now < t0 + super::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(25);
    }
    assert!(
        world.usb_auth_total() > sessions_before,
        "USB reauthenticated"
    );
    assert_eq!(world.snaps[0].adopted_network, new_network);
    assert_eq!(world.snaps[1].adopted_network, old_network);
    assert_eq!(world.snaps[2].adopted_network, old_network);
    let progress = cutover_progress(&world, &operation_id);
    assert!(
        progress.unknown >= 2,
        "partitioned island stays unknown: {progress:?}"
    );
    world.switch.heal(0);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
    let leaf_rx = world.snaps[1].rx_count;
    world.peers[0].app_send(NODE_A, b"c5-down");
    world.pump_until(3000, |snaps| snaps[1].rx_count > leaf_rx);
    assert!(world.snaps[1].rx_count > leaf_rx, "new-epoch downlink");
    world.peers[1].app_send(testkit::GATEWAY, b"c5-upxxx");
    world.pump_until(3000, |snaps| {
        snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "new-epoch uplink"
    );
}

/// C6: after PREPARE, move the tree from G—B—A to G—A—B. The
/// COMMIT frontier must use the new parent reports, then every
/// target adopts without a direct G—B radio leg.
#[test]
fn mesh_c6_route_change_mid_cutover() {
    let Some(mut world) = MeshWorld::start("c6", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "c6 cutover");
    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, "c6");
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }
    assert!(
        world
            .cutover_targets(&operation_id)
            .iter()
            .all(|(_, state, _, _)| state == "prepared"),
        "Host has every PREPARED before the route flips"
    );
    let direct_before = world.switch.leg_delivered[2][0];
    world.switch.set_audible(0, 2, false);
    world.switch.set_audible(2, 0, false);
    world.switch.set_audible(0, 1, true);
    world.switch.set_audible(1, 0, true);
    // Field power cycling clears the old link contexts while NVS keeps
    // PREPARE. Each peer then forms its next hop over the changed air.
    for index in [0, 1, 2] {
        let before = world.peers[index].reboots;
        world.peers[index].power_cut();
        world.step(25);
        assert!(world.peers[index].reboots > before);
        for _ in 0..200 {
            world.step(25);
        }
    }
    for _ in 0..1200 {
        world.step(25);
    }
    let (operation_id, next_gk, new_network, _old_network, _t0) =
        cutover_finish_prepare(&mut world, operation_id, staged_at);
    assert_eq!(
        world
            .cutover_route(&operation_id, NODE_A)
            .and_then(|p| p.report)
            .map(|r| r.parent),
        Some(testkit::GATEWAY),
        "A reported the new parent: route={:?} targets={:?} snaps={:?}",
        world.cutover_route(&operation_id, NODE_A),
        world.cutover_targets(&operation_id),
        world.snaps
    );
    assert_eq!(
        world
            .cutover_route(&operation_id, NODE_B)
            .and_then(|p| p.report)
            .map(|r| r.parent),
        Some(NODE_A),
        "B reported the new parent"
    );
    cutover_converged(&mut world, &operation_id, new_network, next_gk, Some(0));
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied, 3, "new tree applied: {progress:?}");
    assert_eq!(world.switch.leg_delivered[2][0], direct_before);
}

#[test]
fn mesh_c6_adopted_leaf_blocks_old_relay() {
    let Some(mut world) = MeshWorld::start("c6-leaf", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_through_commit(&mut world, "c6-leaf");
    let b_report = world
        .cutover_route(&operation_id, NODE_B)
        .and_then(|p| p.report)
        .expect("B has a pre-COMMIT RouteState");
    assert_eq!(b_report.parent, testkit::GATEWAY);
    assert!(b_report.recv_mono_ms + u64::from(b_report.lease_ms) > world.now);
    let b_attempts = world
        .cutover_targets(&operation_id)
        .iter()
        .find(|t| t.0 == NODE_B)
        .unwrap()
        .3;
    // Flip inside the harness step that accepts A's real STORED receipt,
    // before the distributor can release B from the old route plan.
    world.c6_flip_on_a_stored = Some(super::records::parse_op_token(&operation_id).unwrap());
    for _ in 0..4000 {
        world.step(25);
        if world.c6_flipped {
            break;
        }
    }
    assert!(world.c6_flipped, "the receipt triggered the route fault");
    assert!(world
        .cutover_route(&operation_id, NODE_A)
        .is_some_and(|p| p.stored));
    assert_eq!(world.snaps[2].adopted_network, old_network);
    assert_eq!(
        world
            .cutover_targets(&operation_id)
            .iter()
            .find(|t| t.0 == NODE_B)
            .unwrap()
            .3,
        b_attempts,
        "no old-tree COMMIT to B was dispatched after A stored"
    );
    while world.now < t0 + super::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(25);
    }
    assert_eq!(
        world
            .cutover_targets(&operation_id)
            .iter()
            .find(|t| t.0 == NODE_B)
            .unwrap()
            .3,
        b_attempts,
        "stale COMMIT never entered the transport during grace"
    );
    assert_eq!(world.snaps[1].adopted_network, new_network);
    assert_eq!(world.snaps[2].adopted_network, old_network);
    assert!(world
        .cutover_route(&operation_id, NODE_B)
        .is_some_and(|p| p.deferred));
    let progress = cutover_progress(&world, &operation_id);
    assert!(progress.unknown > 0, "B remains unknown: {progress:?}");
    world.switch.set_audible(0, 2, true);
    world.switch.set_audible(2, 0, true);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
    assert!(
        progress.recovered >= 1,
        "uncommitted B recovered: {progress:?}"
    );
}

/// C7: old carriers from A's actual Owner are refused after B adopts,
/// and an old authenticated receipt arriving exactly at D cannot
/// count merely because Host has not yet run its D tick.
#[test]
fn mesh_c7_old_epoch_boundary() {
    let mut switch = Switch::forced_multihop();
    switch.c7_capture = true;
    let Some(mut world) = MeshWorld::start("c7", switch) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "c7 cutover");
    world.peers[0].power_cut();
    world.step(25);
    converge(&mut world, "c7 resume capture");
    world.switch.c7_hold_data = true;
    let b_rx_before = world.snaps[2].rx_count;
    world.peers[1].app_send(NODE_B, b"c7-old-data");
    for _ in 0..400 {
        world.step(25);
        if world.switch.c7_old_data.is_some() {
            break;
        }
    }
    assert!(
        world.switch.c7_old_data.is_some(),
        "old DATA left A on the radio"
    );
    assert_eq!(
        world.snaps[2].rx_count, b_rx_before,
        "held DATA never reached B"
    );
    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, "c7");
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_finish_prepare(&mut world, operation_id, staged_at);
    assert!(
        world.switch.c7_old_discover.is_some(),
        "old GK discover left A"
    );
    assert!(
        world.switch.c7_old_resume.is_some(),
        "old resume left G or A"
    );
    assert!(
        world.switch.c7_old_cert.is_some(),
        "old MemberCert handshake left A"
    );
    world.c7_hold_b_receipt = true;
    // Strand A fully dark while the COMMIT dispatch is still working
    // its way down the tree (the leaf commits last, so its downlink
    // has not landed yet). A stays Prepared on the old epoch.
    world.switch.isolate(1);
    world.switch.c7_hold_data = false;
    // The held B envelope crossed radio and USB, but its business
    // receipt is not delivered to the authority until D sharp.
    for _ in 0..4000 {
        world.step(25);
        if world.c7_old_receipt.is_some() {
            break;
        }
    }
    assert!(world.c7_old_receipt.is_some(), "old B type-7 wire was held");
    assert!(!world
        .cutover_route(&operation_id, NODE_B)
        .is_some_and(|p| p.stored));
    for _ in 0..2000 {
        world.step(25);
        if world.snaps[2].adopted_network == new_network {
            break;
        }
    }
    assert_eq!(
        world.snaps[2].adopted_network, new_network,
        "B adopted during grace"
    );
    assert!(world.now < t0 + super::cutover::CUTOVER_GRACE_MS);
    for _ in 0..10 {
        world.step(25);
    }
    // Only these injected carriers may reach B during the refusal
    // sample; the old gateway's ambient discovery stays off this leg.
    world.switch.set_audible(0, 2, false);
    let before = world.snaps[2].clone();
    let old_data = world.switch.c7_old_data.as_ref().unwrap().clone();
    let old_discover = world.switch.c7_old_discover.as_ref().unwrap().clone();
    let (resume_from, old_resume) = world.switch.c7_old_resume.as_ref().unwrap().clone();
    let old_cert = world.switch.c7_old_cert.as_ref().unwrap().clone();
    assert_eq!(
        u32::from_be_bytes(old_data[12..16].try_into().unwrap()),
        old_network as u32
    );
    assert_eq!(
        u32::from_be_bytes(old_resume[12..16].try_into().unwrap()),
        old_network as u32
    );
    assert_eq!(
        u32::from_be_bytes(old_cert[12..16].try_into().unwrap()),
        old_network as u32
    );
    world.peers[2].send_rx(&world.macs[1], &world.macs[2], &old_data);
    world.peers[2].send_rx(&world.macs[1], &BROADCAST_MAC, &old_discover);
    for _ in 0..4 {
        world.step(25);
    }
    assert_eq!(
        world.snaps[2].rx_count, before.rx_count,
        "old DATA not delivered"
    );
    assert!(
        world.snaps[2].unknown_peer_rx > before.unknown_peer_rx,
        "old DATA has no adopted MAC binding: {:?}",
        world.snaps[2]
    );
    assert!(world.snaps[2].scope_raw_rx > before.scope_raw_rx);
    assert!(
        world.snaps[2].scope_unknown_generation > before.scope_unknown_generation,
        "old GK discovery refused: {:?}",
        world.snaps[2]
    );
    assert_eq!(world.snaps[2].scope_accepted, before.scope_accepted);
    let proxy_rejects = |snap: &MeshSnap| snap.proxy_frames_rejected + snap.proxy_cookie_rejects;
    let before_resume = proxy_rejects(&world.snaps[2]);
    world.peers[2].send_rx(&world.macs[resume_from], &world.macs[2], &old_resume);
    for _ in 0..4 {
        world.step(25);
    }
    assert!(
        proxy_rejects(&world.snaps[2]) > before_resume,
        "old resume was refused by the unbound proxy lane: {:?}",
        world.snaps[2]
    );
    let before_cert = proxy_rejects(&world.snaps[2]);
    world.peers[2].send_rx(&world.macs[1], &world.macs[2], &old_cert);
    for _ in 0..4 {
        world.step(25);
    }
    assert!(
        proxy_rejects(&world.snaps[2]) > before_cert,
        "old MemberCert handshake was refused: {:?}",
        world.snaps[2]
    );
    assert_eq!(
        world.snaps[2].link_sessions, before.link_sessions,
        "old resume/MemberCert must not reestablish a link"
    );
    world.switch.set_audible(0, 2, true);

    let deadline = t0 + super::cutover::CUTOVER_GRACE_MS;
    while world.now + 25 < deadline {
        world.step(25);
    }
    assert!(world.now < deadline);
    let prior = cutover_progress(&world, &operation_id);
    assert_eq!(prior.phase, "committed", "Host has not ticked at D");
    let (kind, bytes) = world.c7_old_receipt.take().unwrap();
    world.now = deadline;
    world.deliver_authority_up(NODE_B, kind, &bytes, deadline);
    assert!(
        !world
            .cutover_route(&operation_id, NODE_B)
            .is_some_and(|p| p.stored),
        "old COMMIT_STORED is refused at D before the Host tick"
    );
    let after = cutover_progress(&world, &operation_id);
    assert_eq!(
        (after.applied, after.recovered),
        (prior.applied, prior.recovered)
    );
    // B and the gateway adopt inside the grace; A's row stays
    // unknown — never a silent applied. The ledger moves only on
    // durable receipts: the gateway releases at plan close, reboots,
    // and both receipts then ride the rebuilt channels — bound the
    // wait on the ledger itself, not just the peer snapshots.
    for _ in 0..16000 {
        world.step(25);
        let progress = cutover_progress(&world, &operation_id);
        if world.snaps[0].adopted_network == new_network
            && world.snaps[2].adopted_network == new_network
            && progress.applied + progress.recovered >= 2
        {
            break;
        }
    }
    assert_eq!(
        world.snaps[2].adopted_network, new_network,
        "B adopted: {:?}",
        world.snaps[2]
    );
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(
        progress.applied + progress.recovered,
        2,
        "A unaccounted: {progress:?}"
    );
    assert_eq!(
        progress.applied, 2,
        "the reachable pair applied, not recovered: {progress:?}"
    );
    assert_eq!(
        world.snaps[1].adopted_network, old_network,
        "A still on the old epoch: {:?}",
        world.snaps[1]
    );

    // The boundary: B's demoted previous generation authenticates for
    // kScopePreviousOverlapMaxMs (30 min) from B's adoption. Hold A
    // dark past it — 250 ms steps keep G↔B carriers inside their
    // routed TTL while the overlap ages out — then heal. Whatever A
    // still is (Prepared-dark or reverted), the only member-scope
    // traffic it can emit is the retired generation: require an actual
    // arrival and B's unknown-generation refusal. The ledger must
    // still resolve A through recovery; an old-epoch straggler cannot
    // be counted as applied.
    let b_demote = world.now.max(t0);
    let boundary = b_demote + 1_800_000 + 60_000;
    while world.now < boundary {
        world.step(250);
    }
    let b_unkgen = world.snaps[2].scope_unknown_generation;
    let b_raw = world.snaps[2].scope_raw_rx;
    world.switch.heal(1);
    // A's first post-heal member frames carry the retired epoch; give
    // the recovery road room to run at full resolution.
    let mut stale_seen = false;
    for _ in 0..9600 {
        world.step(25);
        if world.snaps[2].scope_raw_rx > b_raw {
            stale_seen = true;
        }
        if stale_seen && world.snaps[2].scope_unknown_generation > b_unkgen {
            break;
        }
        if world.snaps[1].adopted_network == new_network {
            break;
        }
    }
    assert!(
        stale_seen && world.snaps[2].scope_unknown_generation > b_unkgen,
        "B received A's old-epoch frame and refused its generation: B={:?} A={:?} unkgen {} > {}",
        world.snaps[2],
        world.snaps[1],
        world.snaps[2].scope_unknown_generation,
        b_unkgen
    );
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    // A resolves through the recovery road or re-emits its durable
    // APPLIED receipt after adoption — either is honest evidence; the
    // verdict that matters is above: it was never applied while it
    // sat dark on the old epoch.
    assert_eq!(
        progress.applied + progress.recovered,
        3,
        "every target resolved past the old-epoch boundary: {progress:?}"
    );
}
