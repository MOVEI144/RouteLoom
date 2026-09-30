//! Peer processes: the Phase-0 legacy joiner peer and the Phase-1
//! Owner mesh peer with its `G` snapshot.

use super::*;

// --- Phase 0: provision one persona through the legacy joiner peer ------------
// The legacy peer speaks the joiner_interop pipe (single site 0 here);
// the drive below mirrors that module's World for one persona at a time
// (relay ups/downs, the decider, the USB-framed authority lane). Each persona
// converges to MemberReady + JoinConfirm + active GK before its slot
// images are dumped for the mesh boot.

pub(super) const LEGACY_RPC_MAX: usize = 4096;
pub(super) const MEMBER_READY: u8 = 2;
pub(super) const AUTH_READY: u8 = 2;
pub(super) const PHASE_ACTIVE: u8 = 1;

pub(super) fn legacy_peer_path() -> Option<std::path::PathBuf> {
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

fn legacy_peer_path_for(node: u64) -> Option<std::path::PathBuf> {
    let key = match node {
        testkit::GATEWAY => "ROUTELOOM_OWNER_PEER_GW",
        NODE_A => "ROUTELOOM_OWNER_PEER_A",
        NODE_B => "ROUTELOOM_OWNER_PEER_B",
        _ => return legacy_peer_path(),
    };
    std::env::var_os(key)
        .map(std::path::PathBuf::from)
        .or_else(legacy_peer_path)
}

pub(super) fn mesh_peer_path() -> Option<std::path::PathBuf> {
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

fn mesh_peer_path_for(node: u64) -> Option<std::path::PathBuf> {
    let key = match node {
        testkit::GATEWAY => "ROUTELOOM_MESH_PEER_GW",
        NODE_A => "ROUTELOOM_MESH_PEER_A",
        NODE_B => "ROUTELOOM_MESH_PEER_B",
        _ => return mesh_peer_path(),
    };
    std::env::var_os(key)
        .map(std::path::PathBuf::from)
        .or_else(mesh_peer_path)
}

pub(super) fn peers_present() -> bool {
    legacy_peer_path().is_some() && mesh_peer_path().is_some()
}

pub(super) struct DeviceKeys {
    pub(super) priv_hex: String,
    pub(super) pub_hex: String,
    pub(super) cert_hex: String,
}

pub(super) fn persona_keys(node: u64, seed: u8) -> DeviceKeys {
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

pub(super) struct LegacyUp {
    pub(super) proxy: u64,
    pub(super) hops: u8,
    pub(super) object: Vec<u8>,
}

pub(super) struct LegacyAuthorityUp {
    pub(super) kind: u8,
    pub(super) bytes: Vec<u8>,
}

#[derive(Default)]
pub(super) struct LegacySnap {
    pub(super) state: u8,
    pub(super) action_pending: bool,
    pub(super) pending_action: u8,
    pub(super) store_site: u64,
    pub(super) last_write_at: u64,
    pub(super) last_read_at: u64,
    pub(super) terminal_at: u64,
}

#[derive(Default)]
pub(super) struct LegacyOwner {
    pub(super) auth_state: u8,
    pub(super) join_confirmed: bool,
    pub(super) gk_current: u32,
    pub(super) lifecycle_phase: u8,
    pub(super) authority_ready: bool,
}

pub(super) struct LegacyTick {
    pub(super) ups: Vec<LegacyUp>,
    pub(super) authority_ups: Vec<LegacyAuthorityUp>,
    pub(super) snap: LegacySnap,
    pub(super) owner: LegacyOwner,
}

pub(super) struct LegacyPeer {
    pub(super) child: Child,
    pub(super) stdin: std::process::ChildStdin,
    pub(super) stdout: std::process::ChildStdout,
}

impl Drop for LegacyPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl LegacyPeer {
    pub(super) fn spawn(persona: &Persona, t0: u64, seed: u64) -> Self {
        let path = legacy_peer_path_for(persona.node)
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

    pub(super) fn send(&mut self, payload: &[u8]) {
        assert!(
            !payload.is_empty() && payload.len() <= LEGACY_RPC_MAX,
            "rpc bound"
        );
        let head = (payload.len() as u16).to_le_bytes();
        self.stdin.write_all(&head).expect("peer input open");
        self.stdin.write_all(payload).expect("peer input open");
        self.stdin.flush().expect("peer input open");
    }

    pub(super) fn recv(&mut self) -> Vec<u8> {
        let mut head = [0u8; 2];
        self.stdout.read_exact(&mut head).expect("peer alive");
        let length = usize::from(u16::from_le_bytes(head));
        assert!((1..=LEGACY_RPC_MAX).contains(&length), "rpc bound");
        let mut payload = vec![0u8; length];
        self.stdout.read_exact(&mut payload).expect("peer alive");
        payload
    }

    pub(super) fn tick(&mut self, now: u64) -> LegacyTick {
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

    pub(super) fn send_down(&mut self, to_proxy: u64, object: &[u8]) {
        assert!(object.len() <= RELAY_OBJECT_MAX, "relay object bound");
        let mut command = vec![b'W', 0];
        command.extend_from_slice(&to_proxy.to_le_bytes());
        command.extend_from_slice(object);
        self.send(&command);
    }

    pub(super) fn send_authority_down(&mut self, kind: u8, bytes: &[u8]) {
        let mut command = vec![b'C', kind];
        command.extend_from_slice(bytes);
        self.send(&command);
    }

    pub(super) fn dump_flash(&mut self) -> Vec<u8> {
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

    pub(super) fn dump_extended(&mut self) -> Vec<u8> {
        self.send(b"X");
        let mut image = Vec::with_capacity(4562);
        for i in 0..4 {
            let payload = self.recv();
            assert_eq!(payload[0], b'X', "extended slot reply");
            let expect_store = if i < 2 { 2 } else { 3 };
            let expect_len = if i < 2 { 672 } else { 1609 };
            assert_eq!(payload[1], expect_store, "extended store id");
            assert_eq!(payload[2], (i % 2) as u8, "extended slot id");
            assert_eq!(payload.len(), 3 + expect_len, "extended slot image");
            image.extend_from_slice(&payload[3..]);
        }
        image
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
pub(super) struct MeshSnap {
    pub(super) mode: u8,
    pub(super) membership: u8,
    pub(super) authority_started: bool,
    pub(super) authority_ready: bool,
    pub(super) join_confirmed: bool,
    pub(super) link_sessions: u32,
    pub(super) end_sessions: u32,
    pub(super) phase: u8,
    pub(super) stores_healthy: bool,
    pub(super) adopted_network: u64,
    pub(super) own_generation: u32,
    pub(super) applied_rs: u32,
    pub(super) applied_gk: u32,
    pub(super) holdoff_remaining_ms: u64,
    pub(super) gk_current: u32,
    pub(super) gk_next: u32,
    pub(super) has_identity: bool,
    pub(super) has_site: bool,
    pub(super) site_generation: u32,
    pub(super) usb_state: u8,
    pub(super) channel: u8,
    pub(super) committed_channel: u8,
    pub(super) tx_overruns: u32,
    pub(super) sends: u32,
    pub(super) journal_kind: u8,
    pub(super) journal_epoch: u32,
    pub(super) journal_detail: u32,
    pub(super) rrs_applied: u32,
    pub(super) recoveries: u32,
    pub(super) rx_count: u32,
    pub(super) rx_src: u64,
    pub(super) rx: Vec<u8>,
    pub(super) app_tx: Vec<MeshAppTx>,
    pub(super) demux_drops: u32,
    pub(super) link_established: u32,
    pub(super) link_failed: u32,
    pub(super) link_last_error: u8,
    pub(super) link_requests: u32,
    pub(super) link_send_failures: u32,
    pub(super) end_established: u32,
    pub(super) end_failed: u32,
    pub(super) end_last_error: u8,
    pub(super) has_discovery: bool,
    pub(super) discovers_rx: u32,
    pub(super) offers_tx: u32,
    pub(super) offers_rx: u32,
    pub(super) proves_rx: u32,
    pub(super) auths_completed: u32,
    pub(super) kind_rejects: u32,
    pub(super) cookie_rejects: u32,
    pub(super) auth_tag_rejects: u32,
    pub(super) send_failures: u32,
    pub(super) scope_raw_rx: u32,
    pub(super) scope_hint_mismatch: u32,
    pub(super) scope_mac_rejected: u32,
    pub(super) scope_unknown_generation: u32,
    pub(super) scope_accepted: u32,
    pub(super) scope_key_unavailable: u32,
    pub(super) scope_budget_dropped: u32,
    /// First 8 bytes of the RLI1 kid (0 without an identity): the
    /// nonsecret fingerprint a revoke must leave untouched (R2).
    pub(super) id_fp: u64,
    /// ZT legs (D04 §5.1): joiner state/error plus the member
    /// proxy's discover/offer/relay counters.
    pub(super) join_state: u8,
    pub(super) join_error: u8,
    pub(super) proxy_disc_rx: u32,
    pub(super) proxy_offers_tx: u32,
    pub(super) proxy_suppressed: u32,
    pub(super) proxy_relays_started: u32,
    pub(super) proxy_relays_completed: u32,
    pub(super) auth_rx: u64,
    pub(super) auth_tx: u64,
    pub(super) strikes: u8,
    pub(super) j_attempts: u32,
    pub(super) j_m1: u32,
    pub(super) j_dropped: u32,
    pub(super) notice_down_live: bool,
    pub(super) unknown_peer_rx: u32,
    pub(super) proxy_frames_rejected: u32,
    pub(super) proxy_cookie_rejects: u32,
    pub(super) probes_tx: u32,
    pub(super) peer_capacity: u32,
    pub(super) stale_expirations: u32,
    pub(super) repair_demands: u32,
    pub(super) neighbor_count: u8,
    pub(super) phases: Vec<u8>,
    pub(super) transit_conflicts: u32,
    pub(super) receipt_conflicts: u32,
    pub(super) no_route: u32,
    pub(super) stale_tx_results: u32,
    pub(super) driver_peers: u8,
    pub(super) queued: u8,
    pub(super) admissions_rejected: u32,
    pub(super) member_starts: u32,
    pub(super) link_request_failures: u32,
    pub(super) owner_polls: u32,
    pub(super) owner_empty_polls: u32,
    pub(super) rx_queue_max: u32,
    pub(super) expiry_slots_scanned: u64,
    pub(super) hop_accept_expired: u64,
    /// Extension frames this terminal refused as UNSUPPORTED (P04).
    pub(super) ext_unsupported: u32,
    pub(super) group_delivered: u32,
    /// Group frames refused (retired GK, revoked sender or relay).
    pub(super) group_rejected: u32,
    /// Armed `W` record-key faults that fired (F01/F02).
    pub(super) key_fault_hits: u32,
    /// The Z send (explicit gateway): endpoint state, send state and
    /// Service reason; 0 before any.
    pub(super) gw_endpoint: u8,
    pub(super) gw_send: u8,
    pub(super) gw_reason: u8,
    /// This node's GatewayDelivery counters (0 without one).
    pub(super) gw_receipts: u32,
    pub(super) gw_sdk_ram_receipts: u32,
    pub(super) gw_mailbox_stored: u32,
    pub(super) gw_resolves_failed: u32,
    /// The channel-plan participant (ParticipantPhase, 0xFF without one),
    /// its active epoch and channel.
    pub(super) plan_phase: u8,
    pub(super) plan_epoch: u32,
    pub(super) plan_channel: u8,
    /// Device API (V2-14): the membership stage, the membership events and
    /// the last cause, the last finished operation and its result, the
    /// connectivity state with its events and reason — counted across the
    /// peer's restarts.
    pub(super) stage: u8,
    pub(super) membership_events: u32,
    pub(super) last_cause: u16,
    pub(super) op_last: u32,
    pub(super) op_result: u16,
    pub(super) connectivity: u8,
    pub(super) connectivity_events: u32,
    pub(super) connectivity_reason: u16,
    /// F05: calls made from inside Device callbacks, and the Busy answers.
    pub(super) reentry_calls: u32,
    pub(super) reentry_busy: u32,
    /// P05: deferred APPLIED requests, completions and refused completions.
    pub(super) applied_requests: u32,
    pub(super) applied_completed: u32,
    pub(super) applied_refused: u32,
    /// The stored JoinPolicy revision (0 before any).
    pub(super) policy_revision: u32,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub(super) struct MeshAppTx {
    pub(super) seq: u64,
    pub(super) state: u8,
    pub(super) reason: String,
}

#[allow(clippy::field_reassign_with_default)]
pub(super) fn parse_mesh_snap(payload: &[u8]) -> MeshSnap {
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
    snap.probes_tx = get_u32(payload, &mut pos);
    snap.peer_capacity = get_u32(payload, &mut pos);
    snap.stale_expirations = get_u32(payload, &mut pos);
    snap.repair_demands = get_u32(payload, &mut pos);
    snap.neighbor_count = payload[pos];
    pos += 1;
    let world_nodes = usize::from(payload[pos]);
    pos += 1;
    assert!((2..=32).contains(&world_nodes), "snapshot world size");
    snap.phases = payload[pos..pos + world_nodes].to_vec();
    pos += world_nodes;
    snap.transit_conflicts = get_u32(payload, &mut pos);
    snap.receipt_conflicts = get_u32(payload, &mut pos);
    snap.no_route = get_u32(payload, &mut pos);
    snap.stale_tx_results = get_u32(payload, &mut pos);
    snap.driver_peers = payload[pos];
    pos += 1;
    snap.queued = payload[pos];
    pos += 1;
    snap.admissions_rejected = get_u32(payload, &mut pos);
    snap.member_starts = get_u32(payload, &mut pos);
    snap.link_request_failures = get_u32(payload, &mut pos);
    snap.owner_polls = get_u32(payload, &mut pos);
    snap.owner_empty_polls = get_u32(payload, &mut pos);
    snap.rx_queue_max = get_u32(payload, &mut pos);
    snap.expiry_slots_scanned = get_u64(payload, &mut pos);
    snap.hop_accept_expired = get_u64(payload, &mut pos);
    snap.ext_unsupported = get_u32(payload, &mut pos);
    snap.group_delivered = get_u32(payload, &mut pos);
    snap.group_rejected = get_u32(payload, &mut pos);
    snap.key_fault_hits = get_u32(payload, &mut pos);
    snap.gw_endpoint = payload[pos];
    snap.gw_send = payload[pos + 1];
    snap.gw_reason = payload[pos + 2];
    pos += 3;
    snap.gw_receipts = get_u32(payload, &mut pos);
    snap.gw_sdk_ram_receipts = get_u32(payload, &mut pos);
    snap.gw_mailbox_stored = get_u32(payload, &mut pos);
    snap.gw_resolves_failed = get_u32(payload, &mut pos);
    snap.plan_phase = payload[pos];
    pos += 1;
    snap.plan_epoch = get_u32(payload, &mut pos);
    snap.plan_channel = payload[pos];
    pos += 1;
    snap.stage = payload[pos];
    pos += 1;
    snap.membership_events = get_u32(payload, &mut pos);
    snap.last_cause = get_u16(payload, &mut pos);
    snap.op_last = get_u32(payload, &mut pos);
    snap.op_result = get_u16(payload, &mut pos);
    snap.connectivity = payload[pos];
    pos += 1;
    snap.connectivity_events = get_u32(payload, &mut pos);
    snap.connectivity_reason = get_u16(payload, &mut pos);
    snap.reentry_calls = get_u32(payload, &mut pos);
    snap.reentry_busy = get_u32(payload, &mut pos);
    snap.applied_requests = get_u32(payload, &mut pos);
    snap.applied_completed = get_u32(payload, &mut pos);
    snap.applied_refused = get_u32(payload, &mut pos);
    snap.policy_revision = get_u32(payload, &mut pos);
    assert_eq!(pos, payload.len(), "G fully consumed");
    snap
}

pub(super) struct MeshTx {
    pub(super) dst_mac: [u8; 6],
    pub(super) bytes: Vec<u8>,
}

pub(super) struct MeshTick {
    pub(super) tx: Vec<MeshTx>,
    pub(super) usb: Vec<u8>,
    pub(super) snap: MeshSnap,
    /// The peer lifecycle-rebooted (exit 42) during this tick and
    /// already runs respawned (the gateway's USB needs a new Hello).
    pub(super) rebooted: bool,
}

pub(super) struct MeshPeer {
    pub(super) child: Child,
    pub(super) stdin: std::process::ChildStdin,
    pub(super) stdout: std::process::ChildStdout,
    pub(super) node: u64,
    pub(super) mac: [u8; 6],
    pub(super) role: u8,
    pub(super) gateway: bool,
    pub(super) flat: bool,
    pub(super) seed: u64,
    pub(super) world_nodes: usize,
    pub(super) usb_secret_hex: String,
    pub(super) nvs_save: std::path::PathBuf,
    pub(super) t0: u64,
    pub(super) booted: bool,
    /// Clean lifecycle reboots (exit 42) respawned so far.
    pub(super) reboots: u32,
    pub(super) switching_cuts: u32,
    /// F02: the next respawn fails its k-th NVS write once (`--nvs-fail`).
    pub(super) nvs_fail_next: Option<u32>,
    /// Scenario arguments appended on every launch (a later `--cap`
    /// overrides the default bitmap).
    pub(super) extra: Vec<String>,
}

impl Drop for MeshPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl MeshPeer {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn(
        persona: &Persona,
        t0: u64,
        seed: u64,
        world_nodes: usize,
        flash: &std::path::Path,
        flash_ext: &std::path::Path,
        usb_secret_hex: &str,
        nvs_save: &std::path::Path,
        flat: bool,
        extra: &[String],
    ) -> Self {
        let mut child = Self::launch(
            persona.node,
            &persona.mac,
            persona.role,
            persona.gateway,
            t0,
            seed,
            world_nodes,
            usb_secret_hex,
            None,
            Some((flash, flash_ext)),
            nvs_save,
            flat,
            None,
            extra,
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
            flat,
            seed,
            world_nodes,
            usb_secret_hex: usb_secret_hex.to_string(),
            nvs_save: nvs_save.to_path_buf(),
            t0,
            booted: false,
            reboots: 0,
            switching_cuts: 0,
            nvs_fail_next: None,
            extra: extra.to_vec(),
        }
    }

    /// Launches the peer process: first boot from the Phase-0 flash
    /// images, reboots from the NVS image the exiting peer saved
    /// (flash surviving the reset, RAM lost — like silicon).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn launch(
        node: u64,
        mac: &[u8; 6],
        role: u8,
        gateway: bool,
        t0: u64,
        seed: u64,
        world_nodes: usize,
        usb_secret_hex: &str,
        nvs_load: Option<&std::path::Path>,
        flash: Option<(&std::path::Path, &std::path::Path)>,
        nvs_save: &std::path::Path,
        flat: bool,
        nvs_fail: Option<u32>,
        extra: &[String],
    ) -> Child {
        let path = mesh_peer_path_for(node)
            .expect("build routeloom_owner_mesh_peer or set ROUTELOOM_MESH_PEER");
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
            .arg("--world-nodes")
            .arg(format!("{world_nodes}"))
            .arg(if gateway { "--gateway" } else { "--member" })
            .arg("--channel")
            .arg("6")
            .arg("--netlow")
            .arg(format!("{:#x}", testkit::NETWORK_LOW))
            .arg("--gw1")
            .arg(format!("{:#x}", testkit::GATEWAY));
        if flat {
            command.arg("--flat");
        }
        if let Some(nvs) = nvs_load {
            command.arg("--nvs-load").arg(nvs);
        }
        if let Some((flash, flash_ext)) = flash {
            command.arg("--flash").arg(flash);
            command.arg("--flash-ext").arg(flash_ext);
        }
        command.arg("--nvs-save").arg(nvs_save);
        if let Some(k) = nvs_fail {
            command.arg("--nvs-fail").arg(format!("{k}"));
        }
        if gateway {
            command.arg("--usb-secret").arg(usb_secret_hex);
            command.arg("--cap").arg(format!("{USB_CAP}"));
        }
        command.args(extra);
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
    pub(super) fn respawn(&mut self, now: u64) {
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
        let extra = self.extra.clone();
        self.child = Self::launch(
            self.node,
            &self.mac,
            self.role,
            self.gateway,
            now,
            self.seed.wrapping_add(u64::from(self.reboots)),
            self.world_nodes,
            &usb_secret_hex,
            Some(&nvs_save),
            None,
            &nvs_save,
            self.flat,
            self.nvs_fail_next.take(),
            &extra,
        );
        self.stdin = self.child.stdin.take().expect("peer stdin");
        self.stdout = self.child.stdout.take().expect("peer stdout");
    }

    pub(super) fn send(&mut self, payload: &[u8]) {
        assert!(!payload.is_empty() && payload.len() <= RPC_MAX, "rpc bound");
        let head = (payload.len() as u16).to_le_bytes();
        self.stdin.write_all(&head).expect("peer input open");
        self.stdin.write_all(payload).expect("peer input open");
        self.stdin.flush().expect("peer input open");
    }

    /// Reads one frame; `None` is a clean peer exit (EOF): the
    /// caller reaps it (a lifecycle reboot respawns, anything else
    /// panics). A mid-frame death is always a crash.
    pub(super) fn recv(&mut self) -> Option<Vec<u8>> {
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

    /// Sends the tick command; `finish_tick` reads its reply.
    pub(super) fn begin_tick(&mut self, now: u64) {
        let mut command = vec![b'T'];
        command.extend_from_slice(&now.to_le_bytes());
        self.send(&command);
    }

    pub(super) fn finish_tick(&mut self, now: u64) -> MeshTick {
        // A power cut after durable Switching can be followed by the
        // lifecycle's adoption reboot on the first resumed tick.
        // Both boots read saved NVS; a third reboot is a loop.
        for attempt in 0..3 {
            if attempt > 0 {
                self.begin_tick(now);
            }
            if let Some(mut tick) = self.recv_tick() {
                assert_eq!(
                    tick.snap.phases.len(),
                    self.world_nodes,
                    "snapshot world size"
                );
                tick.rebooted = attempt > 0;
                return tick;
            }
            self.respawn(now);
        }
        panic!("peer {:x} rebooted three times in one tick", self.node);
    }

    /// Drains one tick's frames; `None` when the peer exited mid-tick
    /// (a lifecycle reboot — the caller respawns and re-drives).
    pub(super) fn recv_tick(&mut self) -> Option<MeshTick> {
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

    pub(super) fn send_rx(&mut self, src_mac: &[u8; 6], dst_mac: &[u8; 6], frame: &[u8]) {
        let mut command = vec![b'R'];
        command.extend_from_slice(src_mac);
        command.extend_from_slice(dst_mac);
        command.extend_from_slice(frame);
        self.send(&command);
    }

    pub(super) fn send_usb(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        for chunk in bytes.chunks(RPC_MAX - 1) {
            let mut command = vec![b'U'];
            command.extend_from_slice(chunk);
            self.send(&command);
        }
    }

    pub(super) fn nvs_image(&mut self) -> Vec<u8> {
        self.send(b"N");
        let reply = self.recv().expect("NVS reply");
        assert_eq!(reply.first(), Some(&b'N'));
        reply[1..].to_vec()
    }

    pub(super) fn send_complete(&mut self, results: &[u8]) {
        if results.is_empty() {
            return;
        }
        let mut command = vec![b'K'];
        command.extend_from_slice(results);
        self.send(&command);
    }

    pub(super) fn app_send(&mut self, dst: u64, payload: &[u8]) {
        assert!((1..=128).contains(&payload.len()), "app payload bound");
        let mut command = vec![b'S'];
        command.extend_from_slice(&dst.to_le_bytes());
        command.extend_from_slice(payload);
        self.send(&command);
    }

    /// Seals one end-protected frame of `frame_type` with this peer's live
    /// sessions, addressed via `next_hop` (P04). Nothing is transmitted:
    /// the caller injects the returned bytes at the next hop.
    pub(super) fn craft_frame(
        &mut self,
        next_hop: u64,
        dst: u64,
        frame_type: u8,
        minor: u8,
        traffic: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut command = vec![b'O'];
        command.extend_from_slice(&next_hop.to_le_bytes());
        command.extend_from_slice(&dst.to_le_bytes());
        command.extend_from_slice(&[frame_type, minor, traffic]);
        command.extend_from_slice(payload);
        self.send(&command);
        let reply = self.recv().expect("craft reply");
        assert_eq!(reply[0], b'o');
        reply[1..].to_vec()
    }

    /// Arms one fault at the next write of NVS record `key` (F01/F02):
    /// 0 fails it once, 1 cuts power before it lands, 2 cuts power after
    /// its commit. A cut respawns the peer from the saved image.
    pub(super) fn arm_key_fault(&mut self, mode: u8, key: &str) {
        let mut command = vec![b'W', mode];
        command.extend_from_slice(key.as_bytes());
        self.send(&command);
    }

    pub(super) fn group_send(&mut self, group: u16, payload: &[u8]) {
        let mut command = vec![b'M'];
        command.extend_from_slice(&group.to_le_bytes());
        command.extend_from_slice(payload);
        self.send(&command);
    }

    pub(super) fn peer_slot(&mut self, command: u8, index: u8) -> (bool, u8) {
        self.send(&[command, index]);
        let reply = self.recv().expect("peer slot reply");
        assert_eq!(reply.len(), 3);
        assert_eq!(reply[0], command.to_ascii_lowercase());
        (reply[1] == 1, reply[2])
    }

    pub(super) fn app_burst(&mut self, count: u8, dst: u64) -> (u8, u8) {
        let mut command = vec![b'H', count];
        command.extend_from_slice(&dst.to_le_bytes());
        self.send(&command);
        let reply = self.recv().expect("app burst reply");
        assert_eq!(reply.len(), 3);
        assert_eq!(reply[0], b'h');
        (reply[1], reply[2])
    }

    pub(super) fn fail_driver_release(&mut self, fail: bool) {
        self.send(&[b'E', u8::from(fail)]);
    }

    /// C4 fault: a field power cut. The peer process takes the same
    /// exit-42 marker as a lifecycle esp_restart, so the next tick
    /// respawns it from the saved NVS image through the production
    /// boot path — RAM state is genuinely gone.
    pub(super) fn power_cut(&mut self) {
        self.send(b"P");
    }

    pub(super) fn cut_after_switching(&mut self) {
        self.send(b"F");
    }

    /// Device::leave (`true`) or Device::request_join: the status code
    /// and the operation id; `None` when the peer lost power inside the
    /// call (an armed `W` fault): it is respawned from its saved image.
    pub(super) fn device_op(&mut self, leave: bool, now: u64) -> Option<(u8, u32)> {
        self.send(if leave { b"L" } else { b"Y" });
        let Some(reply) = self.recv() else {
            self.respawn(now);
            return None;
        };
        assert_eq!(reply.len(), 6);
        assert_eq!(reply[0], if leave { b'l' } else { b'y' });
        Some((reply[1], u32::from_le_bytes([reply[2], reply[3], reply[4], reply[5]])))
    }

    /// Tracked send with a delivery class (0 best effort, 1 reliable) and a
    /// coalesce key (0 none).
    pub(super) fn app_send_with(&mut self, dst: u64, class: u8, key: u16, payload: &[u8]) {
        assert!((1..=128).contains(&payload.len()), "app payload bound");
        let mut command = vec![b'A'];
        command.extend_from_slice(&dst.to_le_bytes());
        command.push(class);
        command.extend_from_slice(&key.to_le_bytes());
        command.extend_from_slice(payload);
        self.send(&command);
    }

    /// This node's APPLIED execution lease.
    pub(super) fn applied_lease(&mut self) -> [u8; 16] {
        self.send(b"C");
        let reply = self.recv().expect("lease reply");
        assert_eq!(reply.len(), 17);
        assert_eq!(reply[0], b'c');
        let mut lease = [0u8; 16];
        lease.copy_from_slice(&reply[1..]);
        lease
    }

    /// Tracked APPLIED send under `lease` (the destination's).
    pub(super) fn applied_send(&mut self, dst: u64, lease: &[u8; 16], payload: &[u8]) {
        let mut command = vec![b'B'];
        command.extend_from_slice(&dst.to_le_bytes());
        command.extend_from_slice(lease);
        command.extend_from_slice(payload);
        self.send(&command);
    }

    /// Defers every APPLIED request here and completes it after `delay_ms`.
    pub(super) fn defer_applied(&mut self, delay_ms: u32) {
        let mut command = vec![b'D'];
        command.extend_from_slice(&delay_ms.to_le_bytes());
        self.send(&command);
    }

    /// F05: try send and leave from inside Device callbacks.
    pub(super) fn probe_reentry(&mut self, on: bool) {
        self.send(&[b'G', u8::from(on)]);
    }

    /// Device::set_join_policy with `holdoff_s` as the removal holdoff:
    /// the status code and the stored revision.
    pub(super) fn set_join_policy(&mut self, holdoff_s: u32, expected: u32) -> (u8, u32) {
        let mut command = vec![b'X'];
        command.extend_from_slice(&holdoff_s.to_le_bytes());
        command.extend_from_slice(&expected.to_le_bytes());
        self.send(&command);
        let reply = self.recv().expect("policy reply");
        assert_eq!(reply.len(), 6);
        assert_eq!(reply[0], b'x');
        (reply[1], u32::from_le_bytes([reply[2], reply[3], reply[4], reply[5]]))
    }

    /// Explicit gateway send (Service=21, SDK_RAM scope) through
    /// `Device::gateway()`: resolve `gateway`, then send once Ready.
    pub(super) fn gateway_send(&mut self, gateway: u64, payload: &[u8]) {
        assert!((1..=96).contains(&payload.len()), "gateway payload bound");
        let mut command = vec![b'Z'];
        command.extend_from_slice(&gateway.to_le_bytes());
        command.extend_from_slice(payload);
        self.send(&command);
    }
}
