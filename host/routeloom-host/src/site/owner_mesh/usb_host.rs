//! The gateway USB host end.

use super::*;

/// Completed authority carriers per pump: (device, kind, bytes).
pub(super) type AuthorityUps = Vec<(u64, CarrierKind, Vec<u8>)>;

/// One queued USB frame plus its join-relay 0x63 correlation: the
/// adapter learns the request id only when the frame actually goes on
/// the wire (production `note_sent` discipline — never for a frame
/// still sitting in this queue).
pub(super) struct PendingFrame {
    pub(super) frame: Frame,
    pub(super) join_note: Option<(Arc<UsbSiteAdapter>, RelayKey, bool)>,
}

/// The gateway USB host end: the production session, framing,
/// authority-fragment and join-relay codecs; only the pump below is
/// test code (it mirrors the production `site_once` relay half: 0x60
/// ups decode through the bound [`UsbSiteAdapter`] into the join lane,
/// 0x62/0x63 end attempts, and 0x61/0x62 downs drain with 0x63
/// correlation — the ZT recovery road for revoked and cutover
/// stragglers, D04 §5.1).
#[allow(dead_code)]
pub(super) struct UsbHost {
    pub(super) session: DeviceSession,
    pub(super) decoder: StreamDecoder,
    pub(super) request: u64,
    pub(super) pending: Vec<PendingFrame>,
    pub(super) hello_node: Option<u64>,
    pub(super) hello_network: Option<u64>,
    pub(super) hello_capability: Option<u32>,
    pub(super) auth_sessions: Vec<u64>,
    pub(super) session_losses: u64,
    pub(super) ups_seen: u64,
    pub(super) downs_sent: u64,
    pub(super) join_ups_seen: u64,
    pub(super) join_downs_sent: u64,
    pub(super) other_host_ops: u64,
    pub(super) data_frames: u64,
    pub(super) diagnostics: u64,
    /// Sim-time of the last inbound wire bytes — the silent-peer
    /// watchdog clock (mirrors `adapter_writer_loop`'s last_rx).
    pub(super) last_rx_ms: u64,
    /// Sim-time of the last `begin()` — paces handshake retries.
    pub(super) last_begin_ms: u64,
    /// Sim-time of the last emitted frame — paces the idle keepalive.
    pub(super) last_tx_ms: u64,
    /// Fault: authority envelopes (GK Updates/Activates, pull answers)
    /// down to this device are dropped before the wire; channel frames
    /// still pass, so its route and channel stay up.
    pub(super) drop_envelopes_to: Option<u64>,
    pub(super) envelopes_dropped: u64,
}

impl UsbHost {
    pub(super) fn new() -> Self {
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
            drop_envelopes_to: None,
            envelopes_dropped: 0,
        }
    }

    pub(super) fn hello_bytes(&mut self, now: u64) -> Vec<u8> {
        self.last_begin_ms = now;
        encode_frame(&self.session.begin()).expect("hello encodes")
    }

    /// Queues one sealed frame; returns its request id for 0x63
    /// correlation (the id is spent even when the frame waits behind
    /// a credit-short head — the device answers the id it sees).
    pub(super) fn queue_data(&mut self, kind: FrameKind, body: Vec<u8>) -> u64 {
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

    pub(super) fn queue_join_down(
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
    pub(super) fn route_join(
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
    pub(super) fn pump(
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
            if sub == Some(SUB_AUTHORITY_DOWN) && self.drop_envelopes_to.is_some() {
                let fragment = routeloom_protocol::host_ops::decode_authority_down(&down.bytes)
                    .expect("down fragment decodes");
                if Some(fragment.device) == self.drop_envelopes_to
                    && fragment.kind == CarrierKind::Envelope
                {
                    self.envelopes_dropped += 1;
                    continue;
                }
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
