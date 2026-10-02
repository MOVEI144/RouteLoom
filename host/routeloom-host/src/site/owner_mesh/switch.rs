//! The switched radio between the mesh peers.

use super::*;

/// Radio topology (G1): the node count and the undirected audible
/// legs. Node 0 is the gateway.
pub(super) struct Topology {
    pub(super) nodes: usize,
    pub(super) edges: Vec<(usize, usize)>,
}

impl Topology {
    /// Every node hears every other.
    pub(super) fn full(nodes: usize) -> Self {
        let edges = (0..nodes)
            .flat_map(|a| (a + 1..nodes).map(move |b| (a, b)))
            .collect();
        Self { nodes, edges }
    }

    /// The chain 0—1—…—(n−1): the last node is n−1 hops from the gateway.
    pub(super) fn line(nodes: usize) -> Self {
        let edges = (1..nodes).map(|b| (b - 1, b)).collect();
        Self { nodes, edges }
    }

    /// G—R1—E and G—R2—E (nodes 0, 1, 2, 3): two disjoint two-hop
    /// paths, no G—E or R1—R2 leg.
    pub(super) fn diamond() -> Self {
        Self {
            nodes: 4,
            edges: vec![(0, 1), (0, 2), (1, 3), (2, 3)],
        }
    }
}

/// Seeded random noise on one directed leg (G4). Parts per million
/// of the frames that cross the leg; jitter adds 0..=`jitter_ms`.
#[derive(Clone, Copy, Default)]
pub(super) struct LegNoise {
    pub(super) loss_ppm: u32,
    pub(super) dup_ppm: u32,
    pub(super) reorder_ppm: u32,
    pub(super) jitter_ms: u64,
}

/// How often the leg noise fired: a noise row passes only if it hit.
#[derive(Clone, Copy, Default, Debug)]
pub(super) struct NoiseHits {
    pub(super) lost: u64,
    pub(super) duplicated: u64,
    pub(super) reordered: u64,
    pub(super) jittered: u64,
}

impl NoiseHits {
    pub(super) fn total(&self) -> u64 {
        self.lost + self.duplicated + self.reordered + self.jittered
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
pub(super) struct Switch {
    pub(super) audible: Vec<Vec<bool>>,
    /// The construction-time matrix: `heal` restores legs from here,
    /// so a forced-multihop world heals back to multi-hop, not to a
    /// direct radio the test never had.
    pub(super) base: Vec<Vec<bool>>,
    /// Sender bytes, counted once per transmission including loss/broadcast.
    pub(super) radio_bytes: u64,
    pub(super) delivered: u64,
    pub(super) dropped: u64,
    /// Drop the next N frames on the directed leg (the sender's
    /// completion reports failure, like lost airtime).
    pub(super) drop_next: Vec<Vec<u32>>,
    /// Deliver the frame but report failure (a lost MAC ACK: the peer
    /// retries while the far side already holds the frame).
    pub(super) ack_drop_next: Vec<Vec<u32>>,
    /// MAC callbacks are separate from airtime and RX, as on the driver.
    pub(super) callback_delay_ms: Vec<Vec<u64>>,
    pub(super) callback_delay_kind: Option<u8>,
    /// Bounded, directed loss of an authenticated Wire frame kind.
    pub(super) drop_wire: Vec<(usize, usize, u8, u32)>,
    pub(super) wire_dropped: u32,
    pub(super) probes_seen: u32,
    pub(super) results_seen: u32,
    pub(super) route_updates_seen: u32,
    /// LR estimate per physical management transmission, including broadcast
    /// once and failed attempts: (wire bytes + fixed MAC/PHY cost) * 32 us.
    pub(super) management_us: Vec<u64>,
    /// Hold frames on the directed leg this long before delivery.
    pub(super) delay_ms: Vec<Vec<u64>>,
    /// Per-leg evidence: what crossed and what the switch ate.
    pub(super) leg_delivered: Vec<Vec<u64>>,
    pub(super) leg_dropped: Vec<Vec<u64>>,
    /// Seeded random noise per directed leg (G4) and what it hit.
    pub(super) noise: Vec<Vec<LegNoise>>,
    pub(super) noise_seed: u64,
    pub(super) noise_rng: u64,
    pub(super) noise_hits: NoiseHits,
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
    /// Wire frames of this type that crossed a leg: (from, to, header).
    pub(super) watch_kind: Option<u8>,
    pub(super) watched: Vec<(usize, usize, Vec<u8>)>,
}

impl Switch {
    pub(super) fn new(topology: &Topology) -> Self {
        let n = topology.nodes;
        let mut audible = vec![vec![false; n]; n];
        for &(a, b) in &topology.edges {
            audible[a][b] = true;
            audible[b][a] = true;
        }
        Self {
            base: audible.clone(),
            audible,
            radio_bytes: 0,
            delivered: 0,
            dropped: 0,
            drop_next: vec![vec![0; n]; n],
            ack_drop_next: vec![vec![0; n]; n],
            callback_delay_ms: vec![vec![0; n]; n],
            callback_delay_kind: None,
            drop_wire: Vec::new(),
            wire_dropped: 0,
            probes_seen: 0,
            results_seen: 0,
            route_updates_seen: 0,
            management_us: vec![0; n],
            delay_ms: vec![vec![0; n]; n],
            leg_delivered: vec![vec![0; n]; n],
            leg_dropped: vec![vec![0; n]; n],
            noise: vec![vec![LegNoise::default(); n]; n],
            noise_seed: 0,
            noise_rng: 0,
            noise_hits: NoiseHits::default(),
            drop_notice_chunks: false,
            notice_chunks_dropped: 0,
            notice_manifests_delivered: 0,
            c7_capture: false,
            c7_hold_data: false,
            c7_old_data: None,
            c7_old_discover: None,
            c7_old_resume: None,
            c7_old_cert: None,
            watch_kind: None,
            watched: Vec::new(),
        }
    }

    /// Keeps the 88-byte header of a watched frame kind that crossed
    /// `from`→`to` (bounded).
    pub(super) fn note_watched(&mut self, from: usize, to: usize, frame: &[u8]) {
        if self.watched.len() < 64
            && frame.len() > 88
            && frame[..3] == *b"RL\x02"
            && Some(frame[4]) == self.watch_kind
        {
            self.watched.push((from, to, frame[..88].to_vec()));
        }
    }

    pub(super) fn direct() -> Self {
        Self::new(&Topology::full(3))
    }

    /// Node count of this radio.
    pub(super) fn nodes(&self) -> usize {
        self.audible.len()
    }

    /// Forced multi-hop: A (1) and the gateway (0) cannot hear each
    /// other in either direction; everything between them relays via B.
    pub(super) fn forced_multihop() -> Self {
        let mut switch = Self::direct();
        switch.audible[0][1] = false;
        switch.audible[1][0] = false;
        switch.base = switch.audible.clone();
        switch
    }

    /// Directed audibility at runtime (partition/heal). A reconnect
    /// never replays frames dropped while the leg was down.
    pub(super) fn set_audible(&mut self, from: usize, to: usize, audible: bool) {
        self.audible[from][to] = audible;
    }

    /// Cut one peer off the air both ways (isolation).
    pub(super) fn isolate(&mut self, peer: usize) {
        for other in 0..self.nodes() {
            self.audible[peer][other] = false;
            self.audible[other][peer] = false;
        }
    }

    /// Reopen one peer's legs to the construction-time matrix.
    pub(super) fn heal(&mut self, peer: usize) {
        for other in 0..self.nodes() {
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

    /// Arms the same noise on every leg with one seed; the draws run in
    /// the switch's fixed delivery order, so a seed replays exactly.
    pub(super) fn set_noise(&mut self, noise: LegNoise, seed: u64) {
        for row in &mut self.noise {
            row.fill(noise);
        }
        self.noise_seed = seed;
        self.noise_rng = seed;
    }

    fn draw(&mut self, bound: u64) -> u64 {
        self.noise_rng = self
            .noise_rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.noise_rng >> 33) % bound
    }

    fn roll(&mut self, ppm: u32) -> bool {
        ppm > 0 && self.draw(1_000_000) < u64::from(ppm)
    }

    /// Whether the leg's noise loses this frame. No draw on a quiet leg,
    /// so an unarmed switch keeps its seeded behaviour unchanged.
    pub(super) fn noise_lost(&mut self, from: usize, to: usize) -> bool {
        let lost = self.roll(self.noise[from][to].loss_ppm);
        self.noise_hits.lost += u64::from(lost);
        lost
    }

    /// Extra hold for a crossing frame (jitter, and a reorder hold of
    /// two 25 ms steps that lets later frames overtake it) and whether
    /// it is delivered twice.
    pub(super) fn noise_cross(&mut self, from: usize, to: usize) -> (u64, bool) {
        let noise = self.noise[from][to];
        let mut hold = 0;
        if noise.jitter_ms > 0 {
            hold = self.draw(noise.jitter_ms + 1);
            self.noise_hits.jittered += u64::from(hold > 0);
        }
        if self.roll(noise.reorder_ppm) {
            hold += 50;
            self.noise_hits.reordered += 1;
        }
        let duplicate = self.roll(noise.dup_ppm);
        self.noise_hits.duplicated += u64::from(duplicate);
        (hold, duplicate)
    }

    pub(super) fn drop_wire_kind(&mut self, from: usize, to: usize, kind: u8, count: u32) {
        self.drop_wire.push((from, to, kind, count));
    }

    pub(super) fn consume_wire_loss(&mut self, from: usize, to: usize, frame: &[u8]) -> bool {
        let kind = if frame.len() >= 5 && frame[..4] == *b"RL\x02\0" {
            frame[4]
        } else if frame.len() >= 44 && frame[..4] == *b"RLD1" {
            frame[5]
        } else {
            return false;
        };
        if let Some(rule) = self
            .drop_wire
            .iter_mut()
            .find(|rule| rule.0 == from && rule.1 == to && rule.2 == kind && rule.3 > 0)
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
