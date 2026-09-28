//! The switched radio between the mesh peers.

use super::*;

/// The switched radio: `audible[from][to]` plus same-channel delivery.
/// Every unicast completion reports whether the switch delivered the
/// frame; broadcasts always succeed (no MAC ACK on broadcast).
///
/// Fault injection (D04 §5.1) is directed and bounded: tests arm a
/// rule at a program point tied to observed host intent (e.g. "COMMIT
/// dispatched to A", read from the production op state) — never by
/// sniffing ciphertext offsets. Every rule carries a counter so the
/// test proves the fault actually hit.
pub(super) struct Switch {
    pub(super) audible: [[bool; 3]; 3],
    /// The construction-time matrix: `heal` restores legs from here,
    /// so a forced-multihop world heals back to multi-hop, not to a
    /// direct radio the test never had.
    pub(super) base: [[bool; 3]; 3],
    pub(super) delivered: u64,
    pub(super) dropped: u64,
    /// Drop the next N frames on the directed leg (the sender's
    /// completion reports failure, like lost airtime).
    pub(super) drop_next: [[u32; 3]; 3],
    /// Deliver the frame but report failure (a lost MAC ACK: the peer
    /// retries while the far side already holds the frame).
    pub(super) ack_drop_next: [[u32; 3]; 3],
    /// MAC callbacks are separate from airtime and RX, as on the driver.
    pub(super) callback_delay_ms: [[u64; 3]; 3],
    pub(super) callback_delay_kind: Option<u8>,
    /// Bounded, directed loss of an authenticated Wire frame kind.
    pub(super) drop_wire: Vec<(usize, usize, u8, u32)>,
    pub(super) wire_dropped: u32,
    pub(super) probes_seen: u32,
    pub(super) results_seen: u32,
    pub(super) route_updates_seen: u32,
    /// Hold frames on the directed leg this long before delivery.
    pub(super) delay_ms: [[u64; 3]; 3],
    /// Per-leg evidence: what crossed and what the switch ate.
    pub(super) leg_delivered: [[u64; 3]; 3],
    pub(super) leg_dropped: [[u64; 3]; 3],
    /// R1: lose only gateway-origin authority object chunks for A.
    pub(super) drop_notice_chunks: bool,
    pub(super) notice_chunks_dropped: u32,
    pub(super) notice_manifests_delivered: u32,
    pub(super) c7_capture: bool,
    pub(super) c7_hold_data: bool,
    pub(super) c7_old_data: Option<Vec<u8>>,
    pub(super) c7_old_discover: Option<Vec<u8>>,
    pub(super) c7_old_resume: Option<(usize, Vec<u8>)>,
    pub(super) c7_old_cert: Option<Vec<u8>>,
}

impl Switch {
    pub(super) fn direct() -> Self {
        Self {
            audible: [[true; 3]; 3],
            base: [[true; 3]; 3],
            delivered: 0,
            dropped: 0,
            drop_next: [[0; 3]; 3],
            ack_drop_next: [[0; 3]; 3],
            callback_delay_ms: [[0; 3]; 3],
            callback_delay_kind: None,
            drop_wire: Vec::new(),
            wire_dropped: 0,
            probes_seen: 0,
            results_seen: 0,
            route_updates_seen: 0,
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
    pub(super) fn forced_multihop() -> Self {
        let mut switch = Self::direct();
        switch.audible[0][1] = false;
        switch.audible[1][0] = false;
        switch.base = switch.audible;
        switch
    }

    /// Directed audibility at runtime (partition/heal). A reconnect
    /// never replays frames dropped while the leg was down.
    pub(super) fn set_audible(&mut self, from: usize, to: usize, audible: bool) {
        self.audible[from][to] = audible;
    }

    /// Cut one peer off the air both ways (isolation).
    pub(super) fn isolate(&mut self, peer: usize) {
        for other in 0..3 {
            self.audible[peer][other] = false;
            self.audible[other][peer] = false;
        }
    }

    /// Reopen one peer's legs to the construction-time matrix.
    pub(super) fn heal(&mut self, peer: usize) {
        for other in 0..3 {
            self.audible[peer][other] = self.base[peer][other];
            self.audible[other][peer] = self.base[other][peer];
        }
    }

    /// Keep actual old-network carriers for C7. A's certificate is in
    /// an EDHOC step 2/3 object; a large object starts in chunk zero.
    pub(super) fn c7_observe(
        &mut self,
        from: usize,
        dst_mac: [u8; 6],
        frame: &[u8],
        b_mac: [u8; 6],
    ) {
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

    pub(super) fn drop_wire_kind(&mut self, from: usize, to: usize, kind: u8, count: u32) {
        self.drop_wire.push((from, to, kind, count));
    }

    pub(super) fn consume_wire_loss(&mut self, from: usize, to: usize, frame: &[u8]) -> bool {
        if frame.len() < 5 || frame[..4] != *b"RL\x02\0" {
            return false;
        }
        if let Some(rule) = self
            .drop_wire
            .iter_mut()
            .find(|rule| rule.0 == from && rule.1 == to && rule.2 == frame[4] && rule.3 > 0)
        {
            rule.3 -= 1;
            self.wire_dropped += 1;
            return true;
        }
        false
    }
}

pub(super) fn notice_object_frame(frame: &[u8], kind: u8) -> bool {
    // The immutable wire header identifies the target and carrier type;
    // the authority envelope and its encrypted chunks remain opaque.
    frame.len() >= 32
        && frame[0..4] == [b'R', b'L', 2, 0]
        && frame[4] == kind
        && frame[16..24] == testkit::GATEWAY.to_be_bytes()
        && frame[24..32] == NODE_A.to_be_bytes()
}
