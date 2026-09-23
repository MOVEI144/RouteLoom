//! Where join messages come from and go to (docs/design/sdk-v1/02 §7,
//! 07 §4). The Site Authority never touches USB: a gateway adapter turns
//! HostOps 0x40 JoinRelayUp into [`RelayUp`], and the authority's
//! [`Outbound`] items into 0x41 JoinRelayDown / 0x42 JoinRelayAbort.
//!
//! Expected shapes (02 §7.1/§7.2; byte layouts are owned by the USB codec
//! of plan P3-2, not by this module):
//!
//! ```text
//! 0x40 JoinRelayUp   (G→H): gateway u64 | from_proxy u64 | hops u8 | RelayHeader(dir=1) | body
//! 0x41 JoinRelayDown (H→G): to_proxy u64 | RelayHeader(dir=2, status) | body
//! 0x42 JoinRelayAbort (both): proxy u64 | relay_id u32 | reason u8
//! RelayHeader (24 B): ver=1 | dir | relay_id u32 | proxy u64 | joiner MAC 6B |
//!                     step u8 | status u8 | joiner_rssi_dbm i8 | reserved
//! ```
//!
//! `step` is the EDHOC message number 1..4, or 5 for an EDHOC error
//! message; `status` on the way down is 0 continue or 1 final (the proxy
//! frees its slot); aborting is a 0x42 JoinRelayAbort. A gateway joining over its own USB link uses
//! `proxy = gateway`, `hops = 0` (07 §4).
//!
//! The binding to real USB frames is [`UsbJoinRelay`] — deliberately thin
//! and not wired into the daemon's USB lanes yet: the HostOps codec and
//! capability bit (`kCapSiteAuthorityV1`) are being defined concurrently
//! (P3-2). The integrator maps the codec's decoded 0x40 body onto
//! `RelayUp` and encodes each `Outbound` as 0x41/0x42.

use std::sync::{Arc, Mutex};

/// Down-link status of a relayed message. (RelayHeader status 2,
/// "aborted", is never sent as a JoinRelayDown here: an abort is an
/// [`Outbound::Abort`], i.e. 0x42 JoinRelayAbort.)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DownStatus {
    Continue = 0,
    Final = 1,
}

/// `step` of an EDHOC error message on the relay.
pub const STEP_EDHOC_ERROR: u8 = 5;

/// JoinRelayAbort reasons (provisional — the P3-2 codec owns the values).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AbortReason {
    /// Authority at its concurrent-join bound or the joiner is rate
    /// limited (02 §8 M1: "busy", no EDHOC session exists yet).
    Busy = 1,
    /// A message for a relay the authority does not know (expired or
    /// never started).
    UnknownRelay = 2,
    /// The exchange ran past its time bound.
    Timeout = 3,
    /// Internal failure (e.g. the SAK signer failed).
    AuthorityError = 4,
}

/// Identifies one relayed exchange: the proxy's relay slot and the MAC it
/// observed (02 §7.1). Unauthenticated routing data, never evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RelayKey {
    pub gateway: u64,
    pub proxy: u64,
    pub relay_id: u32,
    pub joiner_mac: [u8; 6],
}

/// One message up from a joiner (decoded 0x40).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayUp {
    pub key: RelayKey,
    /// Proxy → gateway hops as the gateway reported (display only).
    pub hops: u8,
    pub step: u8,
    /// Proxy-observed RSSI of the joiner (display only, unauthenticated).
    pub joiner_rssi_dbm: i8,
    pub body: Vec<u8>,
}

/// One message down to a joiner (encode as 0x41).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayDown {
    pub key: RelayKey,
    pub step: u8,
    pub status: DownStatus,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outbound {
    Down(RelayDown),
    /// Encode as 0x42 JoinRelayAbort.
    Abort {
        key: RelayKey,
        reason: AbortReason,
    },
}

/// Delivers the authority's outbound messages. Implementations must not
/// block (the authority calls them with its lock released, but a slow
/// transport would still stall the join driver).
pub trait JoinTransport: Send + Sync {
    fn deliver(&self, outbound: Outbound);
}

/// In-process transport for tests and simulations: collects everything
/// the authority sends.
#[derive(Default)]
pub struct InProcessTransport {
    sent: Mutex<Vec<Outbound>>,
}

impl InProcessTransport {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Everything sent since the last call.
    pub fn take(&self) -> Vec<Outbound> {
        std::mem::take(&mut *self.sent.lock().expect("transport poisoned"))
    }
}

impl JoinTransport for InProcessTransport {
    fn deliver(&self, outbound: Outbound) {
        self.sent.lock().expect("transport poisoned").push(outbound);
    }
}

/// USB binding placeholder: forwards to a frame sink the integrator
/// supplies (the daemon's single-writer outbound queue), one callback per
/// `Outbound`. Until the P3-2 codec lands the daemon constructs the
/// authority with no USB transport and joins arrive only in-process.
pub struct UsbJoinRelay<F: Fn(Outbound) + Send + Sync> {
    sink: F,
}

impl<F: Fn(Outbound) + Send + Sync> UsbJoinRelay<F> {
    pub fn new(sink: F) -> Self {
        Self { sink }
    }
}

impl<F: Fn(Outbound) + Send + Sync> JoinTransport for UsbJoinRelay<F> {
    fn deliver(&self, outbound: Outbound) {
        (self.sink)(outbound);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_usb_binding_forwards_every_outbound() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let relay = UsbJoinRelay::new(move |o| sink.lock().unwrap().push(o));
        let key = RelayKey {
            gateway: 1,
            proxy: 2,
            relay_id: 3,
            joiner_mac: [4; 6],
        };
        relay.deliver(Outbound::Abort {
            key,
            reason: AbortReason::Busy,
        });
        relay.deliver(Outbound::Down(RelayDown {
            key,
            step: 2,
            status: DownStatus::Continue,
            body: vec![0x40],
        }));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }
}
