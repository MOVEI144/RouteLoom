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
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use routeloom_client::api1::RouteLoomTransport;
use routeloom_client::site::{Assignment, KGuardMock, Role};
use routeloom_protocol::authority::CarrierKind;
use routeloom_protocol::host_ops::{SUB_AUTHORITY_DOWN, SUB_AUTHORITY_UP, SUB_SITE_STATE_SET};
use routeloom_protocol::join_relay::{
    RelayBody, RelayDirection, RelayHeader, RelayObject, RelayState, PHASE_EDHOC, RELAY_OBJECT_MAX,
};
use routeloom_protocol::{encode_frame, Frame, FrameKind, StreamDecoder};
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
use routeloom_provision::signer::{test_keypair, RootSigner};

use super::group_keys::HostTime;
use super::store::SqliteSiteStore;
use super::testkit;
use super::transport::{DownStatus, InProcessTransport, Outbound, RelayKey, RelayUp};
use super::usb::{authority_sub, UsbAuthorityAdapter};
use super::{ChannelGroupKeyTransport, SiteAuthority, SiteService};
use crate::acl::Acl;
use crate::{now_ms, serve_client, DeviceSession, State};

// --- Personas ----------------------------------------------------------------
// The gateway is the site's configured gateway (testkit::GATEWAY); the two
// members are relay-capable mesh nodes. MACs are locally-administered and
// unique per process (each peer sets its own stub station MAC).

const NODE_A: u64 = 0x00A1_0000_0000_0101;
const NODE_B: u64 = 0x00A1_0000_0000_0102;
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
}

impl Drop for MeshSite {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl MeshSite {
    fn start(tag: &str, now: u64) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-owner-mesh-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut setup = testkit::setup();
        setup.channel = 6;
        let store = SqliteSiteStore::open(&dir.join("site.db")).unwrap();
        let authority =
            SiteAuthority::open(&setup, Box::new(testkit::sak()), Box::new(store), now).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let acl = Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"{:016x}\":[\"MEMBERSHIP_READ\",\"MEMBERSHIP_DECIDE\",\"MEMBERSHIP_ADMIN\"]}}}},\"7\":{{\"networks\":{{\"*\":[\"MEMBERSHIP_READ\"]}}}}}}}}",
            testkit::NETWORK_LOW
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
        let link = RouteLoomTransport::new(&socket, u64::from(testkit::NETWORK_LOW));
        Self {
            service,
            transport,
            link,
            kguard: KGuardMock::default(),
            dir,
        }
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
            "persona {:x} MemberReady",
            persona.node
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
                    let bytes = Self::down_object(&down.key, down.step, down.status, down.body);
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
        assert_eq!(
            status.code(),
            Some(42),
            "mesh peer {:x} crashed (not a lifecycle reboot): {status:?}",
            self.node
        );
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
        // A lifecycle AdoptNetwork reboots the peer mid-tick; the
        // respawned process answers the same tick from its saved NVS
        // image. More than one reboot per tick is a reboot loop.
        for attempt in 0..2 {
            let mut command = vec![b'T'];
            command.extend_from_slice(&now.to_le_bytes());
            self.send(&command);
            if let Some(mut tick) = self.recv_tick() {
                tick.rebooted = attempt > 0;
                return tick;
            }
            self.respawn(now);
        }
        panic!("peer {:x} rebooted twice in one tick", self.node);
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
}

/// The switched radio: `audible[from][to]` plus same-channel delivery.
/// Every unicast completion reports whether the switch delivered the
/// frame; broadcasts always succeed (no MAC ACK on broadcast).
struct Switch {
    audible: [[bool; 3]; 3],
    delivered: u64,
    dropped: u64,
}

impl Switch {
    fn direct() -> Self {
        Self {
            audible: [[true; 3]; 3],
            delivered: 0,
            dropped: 0,
        }
    }

    /// Forced multi-hop: A (1) and the gateway (0) cannot hear each
    /// other in either direction; everything between them relays via B.
    fn forced_multihop() -> Self {
        let mut switch = Self::direct();
        switch.audible[0][1] = false;
        switch.audible[1][0] = false;
        switch
    }
}

const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// Completed authority carriers per pump: (device, kind, bytes).
type AuthorityUps = Vec<(u64, CarrierKind, Vec<u8>)>;
/// One switched radio delivery: (to_peer, src_mac, dst_mac, frame).
type SwitchDelivery = (usize, [u8; 6], [u8; 6], Vec<u8>);

/// The gateway USB host end: the production session, framing and
/// authority-fragment codecs; only the pump below is test code.
#[allow(dead_code)]
struct UsbHost {
    session: DeviceSession,
    decoder: StreamDecoder,
    request: u64,
    pending: Vec<Frame>,
    hello_node: Option<u64>,
    hello_network: Option<u64>,
    hello_capability: Option<u32>,
    auth_sessions: Vec<u64>,
    session_losses: u64,
    ups_seen: u64,
    downs_sent: u64,
    other_host_ops: u64,
    data_frames: u64,
    diagnostics: u64,
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
            other_host_ops: 0,
            data_frames: 0,
            diagnostics: 0,
        }
    }

    fn hello_bytes(&mut self) -> Vec<u8> {
        encode_frame(&self.session.begin()).expect("hello encodes")
    }

    fn queue_data(&mut self, kind: FrameKind, body: Vec<u8>) {
        let request = self.request;
        self.request += 1;
        self.pending.push(Frame {
            kind,
            flags: 0,
            session: 0,
            request,
            body,
        });
    }

    /// Feeds device bytes, routes verified inners, and returns the bytes
    /// to write back. Authority ups are assembled through `adapter` and
    /// completed carriers are returned for the authority.
    fn pump(
        &mut self,
        bytes: &[u8],
        now: u64,
        adapter: &UsbAuthorityAdapter,
    ) -> (Vec<u8>, AuthorityUps) {
        let mut out = Vec::new();
        let mut completed = Vec::new();
        for decoded in self.decoder.push_timed(bytes, now) {
            let frame = decoded.expect("device USB bytes decode");
            let kind = frame.kind;
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
                        for up in adapter.handle_up(&inner, now).expect("up assembles") {
                            completed.push((up.device, up.kind, up.bytes));
                        }
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
        for down in adapter.take_ready(crate::mono_ms()) {
            let sub = authority_sub(&down.bytes);
            if sub != Some(SUB_AUTHORITY_DOWN) && sub != Some(SUB_SITE_STATE_SET) {
                continue;
            }
            self.queue_data(FrameKind::HostOps, down.bytes);
            self.downs_sent += 1;
        }
        let mut kept = Vec::new();
        for mut frame in self.pending.drain(..) {
            if self.session.protect(&mut frame).is_ok() {
                out.extend_from_slice(&encode_frame(&frame).expect("pending encodes"));
            } else {
                kept.push(frame);
                break;
            }
        }
        // `protect` consumes credit in wire order: anything after the
        // first refused frame keeps its place behind it.
        let drained: Vec<Frame> = self.pending.drain(..).collect();
        kept.extend(drained);
        self.pending = kept;
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
    step_count: u64,
    trace: bool,
    /// Test-held boots: a gated peer's process is spawned but never
    /// ticked (off the air) until the test releases it. Used where a
    /// contender must wait for another peer's channel, not just a
    /// wall-clock offset.
    gate: [bool; 3],
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
            step_count: 0,
            trace: std::env::var_os("ROUTELOOM_MESH_TRACE").is_some(),
            gate: [false; 3],
        };
        // The USB Hello goes out before the first tick; the gateway
        // answers from its pump.
        let hello = world.usb_host.hello_bytes();
        world.peers[0].send_usb(&hello);
        Some(world)
    }

    /// One virtual step: tick every booted peer, switch the radio
    /// frames, pump the gateway USB into the authority, tick the
    /// authority. Peers whose boot time has not come are off the air:
    /// their MACs do not exist yet and frames to them drop.
    fn step(&mut self, dt_ms: u64) {
        self.now += dt_ms;
        self.step_count += 1;
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
        // A rebooted gateway answers on a fresh USB session: re-Hello
        // so it re-authenticates (the old session's pending frames
        // wait behind the handshake, like a field replug).
        if ticks[0].as_ref().is_some_and(|t| t.rebooted) {
            let hello = self.usb_host.hello_bytes();
            self.peers[0].send_usb(&hello);
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
        for (from, tick) in ticks.iter().enumerate() {
            let Some(tick) = tick else { continue };
            for tx in &tick.tx {
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
                        }
                    }
                    continue;
                }
                let to = (0..3).find(|to| self.macs[*to] == tx.dst_mac);
                match to {
                    Some(to)
                        if to != from
                            && booted[to]
                            && self.switch.audible[from][to]
                            && channels[to] == channels[from] =>
                    {
                        deliveries.push((to, self.macs[from], tx.dst_mac, tx.bytes.clone()));
                        completions[from].push(1);
                        self.switch.delivered += 1;
                    }
                    _ => {
                        completions[from].push(0);
                        self.switch.dropped += 1;
                    }
                }
            }
        }
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
        let gw_usb = ticks[0].as_ref().map(|t| t.usb.as_slice()).unwrap_or(&[]);
        let (usb_out, completed) = self.usb_host.pump(gw_usb, self.now, &adapter);
        self.peers[0].send_usb(&usb_out);
        for (device, kind, bytes) in completed {
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
                &bytes,
                HostTime::sync(self.now),
                &mut rng,
            );
            self.rng_state = state;
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
        let tx_total: usize = ticks.iter().flatten().map(|t| t.tx.len()).sum();
        if self.trace && (tx_total > 0 || self.step_count % 20 == 0) {
            let tx_len = |index: usize| ticks[index].as_ref().map(|t| t.tx.len()).unwrap_or(0);
            let usb_len = ticks[0].as_ref().map(|t| t.usb.len()).unwrap_or(0);
            eprintln!(
                "mesh t={} step={} tx=[{},{},{}] usb_out={} usb_in(auth={} ups={} downs={} lost={}) sw(deliv={} drop={})",
                self.now,
                self.step_count,
                tx_len(0),
                tx_len(1),
                tx_len(2),
                usb_len,
                self.usb_host.auth_sessions.len(),
                self.usb_host.ups_seen,
                self.usb_host.downs_sent,
                self.usb_host.session_losses,
                self.switch.delivered,
                self.switch.dropped,
            );
            for (from, tick) in ticks.iter().enumerate() {
                let Some(tick) = tick else { continue };
                for tx in &tick.tx {
                    let head = tx.bytes.iter().take(8).fold(String::new(), |mut o, b| {
                        use std::fmt::Write as _;
                        let _ = write!(o, "{b:02x}");
                        o
                    });
                    eprintln!(
                        "  tx from={from} dst={} len={} head={head}",
                        hex(&tx.dst_mac),
                        tx.bytes.len()
                    );
                }
            }
            for (index, snap) in self.snaps.iter().enumerate() {
                eprintln!(
                    "  peer{index}: mode={} ph={} a_start={} a_ready={} conf={} \
                     link={} end={} net={:#x} gk={}/{} site={} usb={} ch={} sends={} \
                     demux={} le={} lf={} leerr={} lreq={} lsf={} ee={} ef={} eeerr={} \
                     disc={} orx={} otx={} prx={} authc={} krej={} crej={} trej={} sfail={} \
                     sraw={} shint={} smac={} sgen={} sacc={} skey={} sbud={}",
                    snap.mode,
                    snap.phase,
                    snap.authority_started as u8,
                    snap.authority_ready as u8,
                    snap.join_confirmed as u8,
                    snap.link_sessions,
                    snap.end_sessions,
                    snap.adopted_network,
                    snap.gk_current,
                    snap.gk_next,
                    snap.has_site as u8,
                    snap.usb_state,
                    snap.channel,
                    snap.sends,
                    snap.demux_drops,
                    snap.link_established,
                    snap.link_failed,
                    snap.link_last_error,
                    snap.link_requests,
                    snap.link_send_failures,
                    snap.end_established,
                    snap.end_failed,
                    snap.end_last_error,
                    snap.has_discovery as u8,
                    snap.offers_rx,
                    snap.offers_tx,
                    snap.proves_rx,
                    snap.auths_completed,
                    snap.kind_rejects,
                    snap.cookie_rejects,
                    snap.auth_tag_rejects,
                    snap.send_failures,
                    snap.scope_raw_rx,
                    snap.scope_hint_mismatch,
                    snap.scope_mac_rejected,
                    snap.scope_unknown_generation,
                    snap.scope_accepted,
                    snap.scope_key_unavailable,
                    snap.scope_budget_dropped,
                );
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

/// #168 revoke over the real mesh: removing member B delivers the
/// SAK-signed RemovalNotice through the gateway USB relay and the
/// radio to B's real lifecycle, which erases the site trust and
/// enters the 600 s holdoff, while the survivors apply the RRS.
#[test]
fn mesh_revoke_delivers_notice_and_erases() {
    use routeloom_client::site::{RemovalReason, SiteAdmin};
    let Some(mut world) = MeshWorld::start("revoke", Switch::direct()) else {
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
        "mesh converged before revoke"
    );
    let gw_rrs = world.snaps[0].rrs_applied;
    let a_rrs = world.snaps[1].rrs_applied;

    let row = world.member_row(NODE_B).expect("member row");
    let outcome = world
        .provision
        .site
        .link
        .revoke(
            NODE_B,
            row.generation,
            RemovalReason::Removed,
            "mesh-revoke-1",
        )
        .expect("revoke commits");
    assert_eq!(outcome.state, "committed");

    // Notice → Removing: B's real lifecycle got it over the channel.
    world.pump_until(8000, |snaps| snaps[2].phase == PHASE_REMOVING);
    assert_eq!(
        world.snaps[2].phase, PHASE_REMOVING,
        "B removing: {:?}",
        world.snaps[2]
    );
    // Removing → Holdoff with the site trust erased.
    world.pump_until(8000, |snaps| snaps[2].phase == PHASE_HOLDOFF);
    let b = &world.snaps[2];
    assert_eq!(b.phase, PHASE_HOLDOFF, "B holdoff: {b:?}");
    assert!(!b.has_site, "B erased its site trust");
    assert!(
        b.holdoff_remaining_ms > 0,
        "holdoff runs after erasure: {}",
        b.holdoff_remaining_ms
    );
    // Survivors applied the revocation set. The gateway holds its own
    // enforcement while the notice transfer to B is live (best-effort
    // retries bounded), then retires B and completes the apply.
    world.pump_until(8000, |snaps| {
        snaps[0].rrs_applied > gw_rrs && snaps[1].rrs_applied > a_rrs
    });
    assert!(
        world.snaps[0].rrs_applied > gw_rrs,
        "gateway applied the RRS: {:?}",
        world.snaps[0]
    );
    assert!(
        world.snaps[1].rrs_applied > a_rrs,
        "survivor A applied the RRS: {:?}",
        world.snaps[1]
    );
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

    // Past the window the commit lands; all adopt the new network,
    // its GK, and re-open the channel there (USB re-auth included).
    for _ in 0..(super::cutover::CUTOVER_PREPARE_WINDOW_MS / 1000 + 10) {
        world.step(1000);
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
        assert!(snap.authority_ready, "peer {index} channel re-open");
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
        world.usb_host.auth_sessions.len(),
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
