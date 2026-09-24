//! Where join messages come from and go to (docs/design/sdk-v1/02 §7,
//! 07 §4). The Site Authority never touches USB: a gateway adapter turns
//! HostOps 0x60 JoinRelayUp into [`RelayUp`], and the authority's
//! [`Outbound`] items into 0x61 JoinRelayDown / abort bodies
//! (`routeloom-protocol::join_relay`, the byte-level codec shared with the
//! device's `UsbBridge::attach_join_relay`).
//!
//! ```text
//! 0x60 JoinRelayUp   (G→H): gateway u64 | from_proxy u64 | hops u8 | RelayHeader(dir=1) | body
//! 0x61 JoinRelayDown (H→G): to_proxy u64 | RelayHeader(dir=2, status) | body
//! 0x62 JoinRelayAbort (both): proxy u64 | relay_id u32 | reason u8
//! 0x63 JoinRelayResult (G→H): result u16 | proxy u64 | relay_id u32
//! RelayHeader (24 B): ver=1 | dir | relay_id u32 | proxy u64 | joiner MAC 6B |
//!                     step u8 | state u8 | joiner_rssi_dbm i8 | phase u8
//! ```
//!
//! `step` is the EDHOC message number 1..4, or 5 for an EDHOC error
//! message; `state` on the way down is 0 continue, 1 final (the proxy
//! frees its slot) or 2 abort (the body is a status hint, never a
//! message). A gateway joining over its own USB link uses
//! `proxy = gateway`, `hops = 0` (07 §4).
//!
//! The binding to real USB frames is [`super::usb::UsbSiteAdapter`]:
//! `deliver` admits one encoded frame into its bounded down queue (8
//! items, one item ≤ 1005 B, TTL 20 s) and reports admission back, so a
//! full link ends the authority attempt instead of dropping it silently.

use std::sync::{Arc, Mutex};

/// Down-link status of a relayed message, sent as the RelayHeader state
/// of a 0x61 JoinRelayDown with a message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DownStatus {
    Continue = 0,
    Final = 1,
}

/// `step` of an EDHOC error message on the relay.
pub const STEP_EDHOC_ERROR: u8 = 5;

/// Why the authority ended a relay without an answer. Provisional and
/// host-local: these values are NEVER cast to USB bytes — the USB
/// adapter maps each variant explicitly onto a 0x61 status-2 body (or a
/// 0x62 reason); see `super::usb` for the table.
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
/// observed (02 §7.1). Unauthenticated routing data, never evidence. The
/// USB adapter binds `gateway` to the authenticated session's gateway
/// identity — a RelayKey never carries a gateway the session did not
/// prove.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RelayKey {
    pub gateway: u64,
    pub proxy: u64,
    pub relay_id: u32,
    pub joiner_mac: [u8; 6],
}

/// One message up from a joiner (decoded 0x60, phase 4 only — the USB
/// adapter refuses phase 5 as P3-5-unsupported before it reaches here).
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

/// One message down to a joiner (encode as 0x61 with a message body).
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
    /// Encode as a 0x61 status-2 Abort body (preferred: it still carries
    /// the status hint to the proxy) or a 0x62 JoinRelayAbort with an
    /// explicitly mapped reason.
    Abort {
        key: RelayKey,
        reason: AbortReason,
    },
}

impl Outbound {
    pub fn key(&self) -> RelayKey {
        match self {
            Self::Down(down) => down.key,
            Self::Abort { key, .. } => *key,
        }
    }
}

/// Why `deliver` refused an outbound message. Every variant ends the
/// authority attempt as failed (`SiteService::with` → `fail_attempt`):
/// the answer cannot reach the device, so the exchange is over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliverReject {
    /// The bounded down queue (8 items) is full.
    QueueFull,
    /// The encoded frame exceeds the 1005 B item bound.
    TooLarge,
    /// The USB session the adapter was bound to is gone.
    Closed,
}

/// Delivers the authority's outbound messages. Implementations must not
/// block (the authority calls them with its lock released, but a slow
/// transport would still stall the join driver) and must not call back
/// into the authority: `SiteService::with` maps a rejection onto
/// `fail_attempt` itself, after the delivery loop, so no callback can
/// run while a transport mutex is held and no delivery recurses.
pub trait JoinTransport: Send + Sync {
    fn deliver(&self, outbound: Outbound) -> Result<(), DeliverReject>;
}

/// In-process transport for tests and simulations: collects everything
/// the authority sends. Unbounded by design — it always admits, so tests
/// never trip the production queue bounds by accident.
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
    fn deliver(&self, outbound: Outbound) -> Result<(), DeliverReject> {
        self.sent.lock().expect("transport poisoned").push(outbound);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::usb::UsbSiteAdapter;
    use super::*;

    fn key() -> RelayKey {
        RelayKey {
            gateway: 1,
            proxy: 2,
            relay_id: 3,
            joiner_mac: [2, 0, 0, 0, 0, 3],
        }
    }

    fn down(key: RelayKey) -> Outbound {
        Outbound::Down(RelayDown {
            key,
            step: 2,
            status: DownStatus::Continue,
            body: vec![0x40],
        })
    }

    #[test]
    fn the_in_process_transport_always_admits() {
        let transport = InProcessTransport::new();
        for _ in 0..32 {
            assert_eq!(transport.deliver(down(key())), Ok(()));
        }
        assert_eq!(transport.take().len(), 32);
        assert!(transport.take().is_empty());
    }

    #[test]
    fn outbound_knows_its_relay() {
        let key = key();
        assert_eq!(down(key).key(), key);
        assert_eq!(
            Outbound::Abort {
                key,
                reason: AbortReason::Busy,
            }
            .key(),
            key
        );
    }

    #[test]
    fn the_usb_adapter_serves_the_transport_contract() {
        // The production transport behind the trait object: one small
        // down admits, and the failure mode is a typed rejection, not a
        // silent drop. Bounds and mapping tables are covered in usb.rs.
        let adapter = UsbSiteAdapter::new(1, 7);
        let transport: &dyn JoinTransport = adapter.as_ref();
        assert_eq!(transport.deliver(down(key())), Ok(()));
        adapter.close();
        assert_eq!(transport.deliver(down(key())), Err(DeliverReject::Closed));
    }
}
