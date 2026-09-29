//! Harness worlds: the Phase-0 provisioning site and the Phase-1 mesh
//! world (peers, switch, gateway USB and Site Authority on one clock).

use super::*;

pub(super) struct Persona {
    pub(super) node: u64,
    pub(super) mac: [u8; 6],
    pub(super) seed: u8,
    pub(super) role: u8,
    pub(super) gateway: bool,
}

/// World size caps (G1): PR worlds up to 6 nodes, nightly up to 32
/// (`ROUTELOOM_E2E_NIGHTLY` set).
pub(super) fn max_nodes() -> usize {
    if std::env::var_os("ROUTELOOM_E2E_NIGHTLY").is_some() {
        32
    } else {
        6
    }
}

/// The gateway, A and B, then members C.. with the same scheme.
pub(super) fn personas(nodes: usize) -> Vec<Persona> {
    let mut personas = vec![
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
            role: if std::env::var_os("ROUTELOOM_MESH_PEER_A").is_some() {
                ROLE_ENDPOINT
            } else {
                ROLE_MEMBER
            },
            gateway: false,
        },
        Persona {
            node: NODE_B,
            mac: MAC_B,
            seed: SEED_B,
            role: ROLE_MEMBER,
            gateway: false,
        },
    ];
    for index in 3..nodes {
        let step = index as u8 - 2;
        let mut mac = MAC_B;
        mac[5] += step;
        personas.push(Persona {
            node: NODE_B + u64::from(step),
            mac,
            seed: SEED_B + step,
            role: ROLE_MEMBER,
            gateway: false,
        });
    }
    personas.truncate(nodes);
    personas
}

/// The compatibility boot plan ([0, 2000, 12000], then +10 s per further
/// node): the clock offsets the three-node worlds booted with before
/// simultaneous opens resolved in the Owners.
pub(super) fn staggered_boot(nodes: usize) -> Vec<u64> {
    (0..nodes as u64)
        .map(|index| match index {
            0 => 0,
            1 => 2000,
            _ => 12000 + (index - 2) * 10_000,
        })
        .collect()
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private world file");
    file.write_all(bytes).expect("write private world file");
}

/// Phase 0 finishes before any mesh peer starts. A separate database and
/// flash image copy gives each world the same committed starting state.
struct Phase0Snapshot {
    now: u64,
    db: Vec<u8>,
    images: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Phase0Snapshot {
    fn build(nodes: usize) -> Self {
        let mut provision = Provision::start(&format!("phase0-{nodes}"), now_ms());
        let images = personas(nodes)
            .iter()
            .enumerate()
            .map(|(index, persona)| {
                let role = if persona.gateway {
                    Role::Gateway
                } else if persona.role == ROLE_ENDPOINT {
                    Role::Endpoint
                } else {
                    Role::Relay
                };
                let (flash, ext) =
                    provision.provision_persona(persona, 0xA101 + index as u64, role);
                (
                    std::fs::read(flash).expect("Phase 0 flash"),
                    std::fs::read(ext).expect("Phase 0 extended flash"),
                )
            })
            .collect();
        Self {
            now: provision.now,
            db: std::fs::read(provision.site.dir.join("site.db")).expect("Phase 0 site DB"),
            images,
        }
    }
}

fn phase0_snapshot(nodes: usize) -> (Arc<Phase0Snapshot>, u64) {
    static SNAPSHOTS: std::sync::OnceLock<
        Mutex<std::collections::BTreeMap<usize, Arc<Phase0Snapshot>>>,
    > = std::sync::OnceLock::new();
    let mut snapshots = SNAPSHOTS
        .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
        .lock()
        .expect("Phase 0 snapshots");
    if let Some(snapshot) = snapshots.get(&nodes) {
        return (Arc::clone(snapshot), 0);
    }
    let started = std::time::Instant::now();
    let snapshot = Arc::new(Phase0Snapshot::build(nodes));
    let elapsed = started.elapsed().as_millis() as u64;
    snapshots.insert(nodes, Arc::clone(&snapshot));
    (snapshot, elapsed)
}

// --- Site --------------------------------------------------------------------

pub(super) struct MeshSite {
    pub(super) service: Arc<SiteService>,
    pub(super) transport: Arc<InProcessTransport>,
    pub(super) link: RouteLoomTransport,
    pub(super) decider: AssignmentTable,
    pub(super) dir: std::path::PathBuf,
    pub(super) listener_stop: Arc<AtomicBool>,
    pub(super) listener_thread: Option<thread::JoinHandle<()>>,
}

impl Drop for MeshSite {
    fn drop(&mut self) {
        self.stop_listener();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl MeshSite {
    pub(super) fn open_service(
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

    pub(super) fn listen(
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

    pub(super) fn stop_listener(&mut self) {
        self.listener_stop.store(true, Ordering::Release);
        if let Some(handle) = self.listener_thread.take() {
            let socket = self.dir.join("api.sock");
            let _ = UnixStream::connect(&socket);
            handle.join().expect("api listener stopped");
            std::fs::remove_file(socket).unwrap();
        }
    }

    pub(super) fn start(tag: &str, now: u64) -> Self {
        Self::start_with_db(tag, now, None)
    }

    fn start_with_db(tag: &str, now: u64, db: Option<&[u8]>) -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!(
            "routeloom-owner-mesh-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("create private world directory");
        if let Some(db) = db {
            write_private(&dir.join("site.db"), db);
        }
        let (service, transport) = Self::open_service(&dir, now);
        let (listener_stop, listener_thread) = Self::listen(&dir, &service);
        let socket = dir.join("api.sock");
        let link = RouteLoomTransport::new(&socket, u64::from(testkit::NETWORK_LOW));
        Self {
            service,
            transport,
            link,
            decider: AssignmentTable::default(),
            dir,
            listener_stop,
            listener_thread: Some(listener_thread),
        }
    }

    pub(super) fn restart(&mut self, now: u64) {
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

/// Phase-0 driver: one shared site, one legacy peer at a time.
pub(super) struct Provision {
    pub(super) site: MeshSite,
    pub(super) usb: Arc<UsbAuthorityAdapter>,
    pub(super) now: u64,
    pub(super) transfer: u32,
    pub(super) rng_state: u64,
}

impl Provision {
    pub(super) fn start(tag: &str, now: u64) -> Self {
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

    fn from_snapshot(tag: &str, snapshot: &Phase0Snapshot) -> Self {
        let now = now_ms().max(snapshot.now);
        let site = MeshSite::start_with_db(tag, now, Some(&snapshot.db));
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

    pub(super) fn down_object(
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
    pub(super) fn provision_persona(
        &mut self,
        persona: &Persona,
        seed: u64,
        role: Role,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        self.site
            .decider
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
        write_private(&flash_path, &peer.dump_flash());
        write_private(&ext_path, &peer.dump_extended());
        (flash_path, ext_path)
    }

    pub(super) fn step_peer(&mut self, peer: &mut LegacyPeer, node: u64, dt_ms: u64) -> LegacyTick {
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
        let _ = self.site.decider.serve_once(&self.site.link).unwrap();
        self.drain(peer);
        tick
    }

    pub(super) fn route_up(&mut self, peer: &mut LegacyPeer, node: u64, up: &LegacyUp) {
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

    pub(super) fn drain(&mut self, peer: &mut LegacyPeer) {
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

    pub(super) fn route_authority_up(&mut self, node: u64, up: &LegacyAuthorityUp) {
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

    pub(super) fn drain_authority_downs(&mut self, peer: &mut LegacyPeer, node: u64) {
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

/// One switched radio delivery: (to_peer, src_mac, dst_mac, frame).
pub(super) type SwitchDelivery = (usize, [u8; 6], [u8; 6], Vec<u8>);

/// Phase-1 world: one Owner peer per topology node (node 0 is the
/// gateway), the switch, the gateway USB host end, and the provisioned
/// site from Phase 0.
pub(super) struct MeshWorld {
    pub(super) peers: Vec<MeshPeer>,
    /// Index → MAC and index → NodeId; `index_of` is the reverse table.
    pub(super) macs: Vec<[u8; 6]>,
    pub(super) nodes: Vec<u64>,
    pub(super) provision: Provision,
    pub(super) usb_host: UsbHost,
    /// The per-gateway hostlink credentials directory the host end reads.
    pub(super) hostlink_dir: std::path::PathBuf,
    pub(super) switch: Switch,
    pub(super) now: u64,
    pub(super) rng_state: u64,
    pub(super) snaps: Vec<MeshSnap>,
    /// Test-held boots: a gated peer's process is spawned but never
    /// ticked (off the air) until the test releases it. Used where a
    /// contender must wait for another peer's channel, not just a
    /// wall-clock offset.
    pub(super) gate: Vec<bool>,
    /// The bound join-relay adapter (ZT recovery road, D04 §5.1):
    /// Phase 0's in-process transport is retired once the mesh boots.
    pub(super) join_adapter: Arc<UsbSiteAdapter>,
    /// USB incarnation shared by both adapter families (one session
    /// serves relay and authority, like the production lane); every
    /// gateway reboot, disconnect or daemon restart takes a new one.
    pub(super) usb_incarnation: u64,
    /// Authenticated USB sessions across rebinds (each rebind starts
    /// a fresh `UsbHost`, so the live count alone would forget).
    pub(super) usb_auth_total: u64,
    /// Delayed switch deliveries: (release_at, delivery).
    pub(super) delayed: Vec<(u64, SwitchDelivery)>,
    /// Per-sender FIFO preserves the ESP-NOW callback attribution order.
    pub(super) callbacks: Vec<Vec<(u64, u8)>>,
    pub(super) early_hop_accepts: u32,
    pub(super) probe_while_callback_pending: u32,
    /// C5 fault: the gateway↔host USB lane physically cut. The
    /// gateway's USB output is swallowed and the host's reply stream
    /// never reaches the bridge — buffered carriers queue like a real
    /// cable pull, and both sides' session timeouts expire naturally.
    pub(super) usb_down: bool,
    /// C6: move the physical tree when the real A receipt reaches Host,
    /// before the next distributor tick may dispatch B's queued COMMIT.
    pub(super) c6_flip_on_a_stored: Option<u64>,
    pub(super) c6_flipped: bool,
    pub(super) c7_hold_b_receipt: bool,
    pub(super) c7_old_receipt: Option<(CarrierKind, Vec<u8>)>,
    /// Run evidence (G6): the tag, boot plan and clocks at start.
    pub(super) tag: String,
    pub(super) boot_ms: Vec<u64>,
    pub(super) started_vt: u64,
    pub(super) started: std::time::Instant,
    pub(super) phase0_wall_ms: u64,
}

impl Drop for MeshWorld {
    fn drop(&mut self) {
        report::write_world(self, !thread::panicking());
    }
}

impl MeshWorld {
    /// `None` when either peer binary is missing: the test skips
    /// (ignore-equivalent). Provisions every persona first.
    pub(super) fn start(tag: &str, switch: Switch) -> Option<Self> {
        Self::start_with_profile(tag, switch, false)
    }

    pub(super) fn start_with_profile(tag: &str, switch: Switch, flat: bool) -> Option<Self> {
        // Every node powers on at the same tick (M05's all-at-once boot):
        // simultaneous opens resolve in the Owners, not by clock offsets.
        let boot_ms = vec![0; switch.nodes()];
        Self::start_plan(tag, switch, &boot_ms, flat)
    }

    /// A world from a scenario's topology (as its switch) and boot plan:
    /// node i powers on `boot_ms[i]` after the mesh phase starts.
    pub(super) fn start_plan(
        tag: &str,
        switch: Switch,
        boot_ms: &[u64],
        flat: bool,
    ) -> Option<Self> {
        let nodes = switch.nodes();
        assert!(
            (2..=max_nodes()).contains(&nodes),
            "{nodes} nodes exceed the world cap {}",
            max_nodes()
        );
        assert_eq!(boot_ms.len(), nodes, "one boot time per node");
        if !peers_present() {
            report::write_not_run(tag);
            eprintln!(
                "SKIP site::owner_mesh: no C++ peers \
                 (build routeloom_owner_mesh_peer + routeloom_joiner_interop_peer, \
                 or set ROUTELOOM_MESH_PEER / ROUTELOOM_OWNER_PEER)"
            );
            return None;
        }
        let started = std::time::Instant::now();
        let (snapshot, phase0_wall_ms) = phase0_snapshot(nodes);
        let provision = Provision::from_snapshot(tag, &snapshot);
        let personas = personas(nodes);
        let images: Vec<_> = snapshot
            .images
            .iter()
            .enumerate()
            .map(|(index, (flash, ext))| {
                let node = personas[index].node;
                let flash_path = provision
                    .site
                    .dir
                    .join(format!("phase0-{node:x}-flash.bin"));
                let ext_path = provision
                    .site
                    .dir
                    .join(format!("phase0-{node:x}-flash-ext.bin"));
                write_private(&flash_path, flash);
                write_private(&ext_path, ext);
                (flash_path, ext_path)
            })
            .collect();
        let now = provision.now;
        // Production credential layout (`--hostlink-credentials`): one
        // private file per gateway, holding a world-specific secret.
        let hostlink_dir = provision.site.dir.join("hostlink");
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&hostlink_dir)
                .expect("hostlink credentials dir");
        }
        let hostlink_secret = format!("hostlink-{:016x}", now ^ 0x5EED_0B11);
        write_private(
            &hostlink_dir.join(format!("{:016x}", testkit::GATEWAY) + ".key"),
            hostlink_secret.as_bytes(),
        );
        let usb_secret_hex = hex(hostlink_secret.as_bytes());
        // Tests that need a channel-ready gate rather than a clock offset
        // hold the peer with `gate` and release it once the relay
        // converged; `staggered_boot` is the compatibility boot plan.
        let mut peers = Vec::with_capacity(nodes);
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
                now + boot_ms[index],
                0xB1E0 + index as u64,
                nodes,
                &images[index].0,
                &images[index].1,
                &usb_secret_hex,
                &nvs_save,
                flat,
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
            macs: personas.iter().map(|p| p.mac).collect(),
            nodes: personas.iter().map(|p| p.node).collect(),
            provision,
            usb_host: UsbHost::new(&hostlink_dir),
            hostlink_dir,
            switch,
            now,
            rng_state: 0x5EED_1234_5678_9ABC,
            snaps: vec![MeshSnap::default(); nodes],
            gate: vec![false; nodes],
            join_adapter,
            usb_incarnation: 7,
            usb_auth_total: 0,
            delayed: Vec::new(),
            callbacks: vec![Vec::new(); nodes],
            early_hop_accepts: 0,
            probe_while_callback_pending: 0,
            usb_down: false,
            c6_flip_on_a_stored: None,
            c6_flipped: false,
            c7_hold_b_receipt: false,
            c7_old_receipt: None,
            tag: tag.to_string(),
            boot_ms: boot_ms.to_vec(),
            started_vt: now,
            started,
            phase0_wall_ms,
        };
        // The USB Hello goes out before the first tick; the gateway
        // answers from its pump.
        let hello = world.usb_host.hello_bytes(world.now);
        world.peers[0].send_usb(&hello);
        Some(world)
    }

    /// Authenticated gateway USB sessions so far, across rebinds.
    pub(super) fn usb_auth_total(&self) -> usize {
        self.usb_auth_total as usize + self.usb_host.auth_sessions.len()
    }

    /// A gateway USB session boundary (reboot, disconnect, daemon
    /// restart): the old session's relays, queues and request mappings
    /// die with their adapters — nothing is carried over and no
    /// adapter is reused across the boundary (production `site_once`
    /// parity, D04 §5.1). The gateway re-authenticates from the fresh
    /// Hello this queues.
    pub(super) fn gateway_usb_rebind(&mut self) {
        self.usb_auth_total += self.usb_host.auth_sessions.len() as u64;
        self.join_adapter.close();
        let _ = self
            .provision
            .site
            .service
            .with(|a| a.drop_gateway_relays(testkit::GATEWAY, self.now));
        self.provision.usb.close();
        self.usb_host = UsbHost::new(&self.hostlink_dir);
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

    pub(super) fn usb_disconnect(&mut self) {
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

    pub(super) fn usb_reconnect(&mut self) {
        self.usb_down = false;
        self.gateway_usb_rebind();
    }

    pub(super) fn daemon_restart(&mut self) {
        self.join_adapter.close();
        self.provision.usb.close();
        self.provision.site.restart(self.now);
        self.gateway_usb_rebind();
    }

    pub(super) fn deliver_authority_up(
        &mut self,
        device: u64,
        kind: CarrierKind,
        bytes: &[u8],
        at: u64,
    ) {
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
    pub(super) fn step(&mut self, dt_ms: u64) {
        self.now += dt_ms;
        let nodes = self.peers.len();
        // B1: every booted peer gets its tick command first and runs in
        // parallel; the replies are then read in index order. A peer's
        // tick depends only on its own inputs, so this is the serial
        // result, faster.
        for (index, peer) in self.peers.iter_mut().enumerate() {
            if !peer.booted && self.now >= peer.t0 && !self.gate[index] {
                peer.booted = true;
            }
            if peer.booted {
                peer.begin_tick(self.now);
            }
        }
        let mut ticks = Vec::with_capacity(nodes);
        for (index, peer) in self.peers.iter_mut().enumerate() {
            ticks.push(if peer.booted {
                Some(peer.finish_tick(self.now))
            } else {
                None
            });
            if ticks[index].as_ref().is_some_and(|tick| tick.rebooted) {
                self.callbacks[index].clear();
            }
        }
        // A rebooted gateway answers on a fresh USB session: a full
        // session boundary (fresh host end, fresh adapters, the
        // gateway re-authenticates from the new Hello).
        if !self.usb_down && ticks[0].as_ref().is_some_and(|t| t.rebooted) {
            self.gateway_usb_rebind();
        }
        // Switch: deliver per audibility + same channel, then report
        // MAC ACKs (unicast succeeds iff delivered).
        let booted: Vec<bool> = ticks.iter().map(Option::is_some).collect();
        let channels: Vec<u8> = ticks
            .iter()
            .map(|t| t.as_ref().map(|t| t.snap.channel).unwrap_or(0))
            .collect();
        let b_mac = self.macs.get(2).copied().unwrap_or(BROADCAST_MAC);
        let mut deliveries: Vec<SwitchDelivery> = Vec::new();
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
                self.switch.c7_observe(from, tx.dst_mac, &tx.bytes, b_mac);
                if tx.dst_mac == BROADCAST_MAC {
                    self.callbacks[from].push((self.now, 1));
                    for to in 0..nodes {
                        if to != from
                            && booted[to]
                            && self.switch.audible[from][to]
                            && channels[to] == channels[from]
                        {
                            if self.switch.noise_lost(from, to) {
                                self.switch.dropped += 1;
                                self.switch.leg_dropped[from][to] += 1;
                                continue;
                            }
                            let (extra, twice) = self.switch.noise_cross(from, to);
                            let delivery = (to, self.macs[from], BROADCAST_MAC, tx.bytes.clone());
                            for delivery in [Some(delivery.clone()), twice.then_some(delivery)]
                                .into_iter()
                                .flatten()
                            {
                                if extra == 0 {
                                    deliveries.push(delivery);
                                } else {
                                    hold.push((self.now + extra, delivery));
                                }
                            }
                            self.switch.delivered += 1;
                            self.switch.leg_delivered[from][to] += 1;
                        }
                    }
                    continue;
                }
                let Some(to) = self.macs.iter().position(|mac| *mac == tx.dst_mac) else {
                    self.callbacks[from].push((self.now, 0));
                    self.switch.dropped += 1;
                    continue;
                };
                if tx.bytes.len() > 4 && tx.bytes[..4] == *b"RL\x02\0" {
                    match tx.bytes[4] {
                        WIRE_PROBE => self.switch.probes_seen += 1,
                        WIRE_RESULT => self.switch.results_seen += 1,
                        WIRE_ROUTE_UPDATE => self.switch.route_updates_seen += 1,
                        _ => {}
                    }
                }
                if tx.bytes.len() > 4
                    && tx.bytes[..4] == *b"RL\x02\0"
                    && tx.bytes[4] == WIRE_HOP_ACCEPT
                    && self.callbacks[to].iter().any(|(at, _)| *at > self.now)
                {
                    self.early_hop_accepts += 1;
                }
                let delay_this = match self.switch.callback_delay_kind {
                    None => true,
                    Some(kind) => {
                        tx.bytes.len() > 4 && tx.bytes[..4] == *b"RL\x02\0" && tx.bytes[4] == kind
                    }
                };
                let callback_delay = if delay_this {
                    self.switch.callback_delay_ms[from][to]
                } else {
                    0
                };
                let callback_at = self.now + callback_delay;
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
                    self.callbacks[from].push((callback_at, 0));
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else if self.switch.drop_notice_chunks && notice_chunk {
                    self.switch.notice_chunks_dropped += 1;
                    self.callbacks[from].push((callback_at, 0));
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else if self.switch.consume_wire_loss(from, to, &tx.bytes) {
                    self.callbacks[from].push((callback_at, 0));
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else if self.switch.drop_next[from][to] > 0 {
                    self.switch.drop_next[from][to] -= 1;
                    self.callbacks[from].push((callback_at, 0));
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else if !leg_up || self.switch.noise_lost(from, to) {
                    self.callbacks[from].push((callback_at, 0));
                    self.switch.dropped += 1;
                    self.switch.leg_dropped[from][to] += 1;
                } else {
                    if from == 2 && to == 1 && notice_object_frame(&tx.bytes, 49) {
                        self.switch.notice_manifests_delivered += 1;
                    }
                    // The frame crosses (now or after the leg's hold);
                    // only the MAC ACK is droppable from here.
                    let (extra, twice) = self.switch.noise_cross(from, to);
                    let release_at = self.now + self.switch.delay_ms[from][to] + extra;
                    let delivery = (to, self.macs[from], tx.dst_mac, tx.bytes.clone());
                    for delivery in [Some(delivery.clone()), twice.then_some(delivery)]
                        .into_iter()
                        .flatten()
                    {
                        if release_at <= self.now {
                            deliveries.push(delivery);
                        } else {
                            hold.push((release_at, delivery));
                        }
                    }
                    if self.switch.ack_drop_next[from][to] > 0 {
                        self.switch.ack_drop_next[from][to] -= 1;
                        self.callbacks[from].push((callback_at, 0));
                    } else {
                        self.callbacks[from].push((callback_at, 1));
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
            if bytes.len() > 4
                && bytes[..4] == *b"RL\x02\0"
                && bytes[4] == WIRE_PROBE
                && self.callbacks[*to].iter().any(|(at, _)| *at > self.now)
            {
                self.probe_while_callback_pending += 1;
            }
            self.peers[*to].send_rx(src, dst, bytes);
        }
        for (index, peer) in self.peers.iter_mut().enumerate() {
            if booted[index] {
                let ready = self.callbacks[index]
                    .iter()
                    .take_while(|(at, _)| *at <= self.now)
                    .count();
                let completions: Vec<u8> = self.callbacks[index]
                    .drain(..ready)
                    .map(|(_, result)| result)
                    .collect();
                peer.send_complete(&completions);
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
            .decider
            .serve_once(&self.provision.site.link);
        for (index, tick) in ticks.iter().enumerate() {
            if let Some(tick) = tick {
                self.snaps[index] = tick.snap.clone();
            }
        }
    }

    pub(super) fn pump_until(&mut self, budget_ticks: u32, done: impl Fn(&[MeshSnap]) -> bool) {
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

    /// The NodeId → peer index table.
    pub(super) fn index_of(&self, node: u64) -> usize {
        self.nodes
            .iter()
            .position(|n| *n == node)
            .unwrap_or_else(|| panic!("node {node:x} is not in this world"))
    }

    pub(super) fn member_row(&self, node: u64) -> Option<crate::site::store::DeviceRow> {
        self.provision
            .site
            .service
            .with(|a| a.devices.get(&node).cloned())
            .0
    }

    pub(super) fn active_gk(&self) -> u32 {
        self.provision.site.service.with(|a| a.gks.active_epoch()).0
    }

    /// One cutover op's live targets: (node, state, prepared_revision,
    /// attempts) — the production record, for dispatch-ordering
    /// evidence (C1: a relay's COMMIT leaves only after its leaf's
    /// COMMIT_STORED lands).
    pub(super) fn cutover_targets(&self, operation_id: &str) -> Vec<(u64, String, u32, u32)> {
        use crate::site::cutover::GrantState;
        let op = crate::site::records::parse_op_token(operation_id).unwrap();
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
    pub(super) fn cutover_route(
        &self,
        operation_id: &str,
        node: u64,
    ) -> Option<crate::site::cutover::CutoverRoutePlan> {
        let op = crate::site::records::parse_op_token(operation_id).unwrap();
        self.provision
            .site
            .service
            .with(|a| a.cutover_routes.get(&(op, node)).cloned())
            .0
    }

    /// One revoke op's notice evidence: (delivery, intent_confirmed).
    /// `None` while the op carries no notice (or no such op).
    pub(super) fn revoke_notice(&self, operation_id: &str) -> Option<(String, bool)> {
        use crate::site::revocation::NoticeDelivery;
        let op = crate::site::records::parse_op_token(operation_id).unwrap();
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

/// Shared convergence: every peer adopted, Active, channel-ready
/// and JoinConfirmed.
pub(super) fn converge(world: &mut MeshWorld, what: &str) {
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
/// the relay converged: `gated` boots into a free flight, so a scenario
/// starts from a known attach order.
pub(super) fn converge_gated(world: &mut MeshWorld, gated: usize, what: &str) {
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
