//! Transport-agnostic mesh facade for applications (KGuard).
//!
//! An application needs exactly four operations from "the network",
//! whatever carries it:
//!
//! 1. [`MeshTransport::send`] — hand a payload to a device, get a handle;
//! 2. [`MeshTransport::receive`] — a stream of payloads from devices;
//! 3. [`MeshTransport::membership`] — a stream of joined / left (and
//!    link-changed) events per device;
//! 4. [`MeshTransport::link_status`] / [`MeshTransport::links`] — per-device
//!    link status: connected or not, last-heard time, radio quality.
//!
//! Optional fifth operation, added without changing the four above:
//! [`MeshTransport::send_group`] / [`MeshTransport::group_result`] — one
//! payload to a group of devices (or all of them, [`GROUP_ALL`]) and the
//! aggregated outcome (how many accepted it, which ones are unconfirmed).
//! Transports without group delivery inherit default methods that answer
//! `Rejected { code: "UNSUPPORTED" }`, so existing implementations keep
//! compiling and behaving as before.
//!
//! The trait names no RouteLoom concept: an ESP-NOW mesh behind a USB
//! gateway ([`api1::RouteLoomTransport`], a thin client of the routeloom-host
//! daemon's API1 socket) and, say, a Wi-Fi/TCP transport implement the same
//! surface, and the application's "no communication" / status-bar logic is
//! written once against [`LinkStatus::connected`].
//!
//! Separately from the mesh facade, [`site::SiteAdmin`] is the KGuard side
//! of the SDK v1 zero-touch join (join requests, verdicts, discovered
//! devices, members, removal); the RouteLoom backend implements it too.
//!
//! Clock domain: every timestamp this crate returns ([`LinkStatus::
//! last_heard_ms`], [`MembershipEvent::at_ms`]) is host wall-clock UNIX
//! milliseconds. The RouteLoom backend derives `last_heard_ms` on the host
//! from the device's reported age (an upper bound on freshness).

use std::fmt;
use std::io;

#[cfg(unix)]
pub mod api1;

/// KGuard's decision surface of the SDK v1 Site Authority (zero-touch
/// join): [`site::SiteAdmin`] and the [`site::KGuardMock`] policy.
pub mod site;

/// Device identity on the transport (RouteLoom: the 64-bit mesh node id).
pub type NodeId = u64;

/// Group address (RouteLoom: 16-bit group id, 1..=0xFFFF). Devices join
/// groups locally in their firmware; the sender does not know the members.
pub type GroupId = u16;

/// The group every device belongs to.
pub const GROUP_ALL: GroupId = 0xFFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// One attempt; loss is possible and not reported as failure.
    BestEffort,
    /// Retransmitted until the destination confirms or the TTL runs out.
    Reliable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendOptions {
    pub delivery: Delivery,
    /// How long the transport may keep trying (RouteLoom: 1..=30000 ms).
    pub ttl_ms: u32,
    /// Relay budget (RouteLoom: 1..=10 hops; transports without relays
    /// ignore it).
    pub hop_limit: u8,
    /// Keep the accepted request across a host restart when supported.
    pub durable: bool,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            delivery: Delivery::Reliable,
            ttl_ms: 5_000,
            hop_limit: 10,
            durable: false,
        }
    }
}

/// Scheduling class of a group send (RouteLoom maps it 1:1 onto the mesh
/// priority; `Urgent` is for alarms and is never held behind other work).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    Bulk,
    Normal,
    Management,
    Urgent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSendOptions {
    pub priority: Priority,
    /// Every receiving device applies this sender's ordered messages in
    /// send order (bounded hold; a gap is skipped after at most the
    /// message lifetime). Unordered messages are never held.
    pub ordered: bool,
    /// Message lifetime (RouteLoom: 1..=30000 ms).
    pub ttl_ms: u32,
    /// Relay budget (RouteLoom: 1..=254).
    pub hop_limit: u8,
    /// How long `send_group` waits for the transport to accept or refuse
    /// the message before returning the in-flight handle (0 = do not wait;
    /// RouteLoom caps it at 15000 ms).
    pub admission_wait_ms: u32,
}

impl Default for GroupSendOptions {
    fn default() -> Self {
        Self {
            priority: Priority::Normal,
            ordered: false,
            ttl_ms: 5_000,
            hop_limit: 10,
            admission_wait_ms: 2_000,
        }
    }
}

impl GroupSendOptions {
    /// An alarm: urgent, unordered.
    pub fn alarm() -> Self {
        Self {
            priority: Priority::Urgent,
            ..Self::default()
        }
    }

    /// A display update: normal priority, applied in send order.
    pub fn ordered_update() -> Self {
        Self {
            ordered: true,
            ..Self::default()
        }
    }
}

/// Where a group send stands. Only the last five are final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupState {
    /// Accepted by the host, not yet accepted by the gateway.
    Pending,
    /// The gateway accepted it and is still confirming devices.
    InProgress,
    /// Every known device confirmed it.
    Delivered,
    /// The transport gave up with devices unconfirmed (see `missing`).
    Failed,
    /// The lifetime ran out (RouteLoom also uses it for "never sent").
    Expired,
    /// Refused before anything was transmitted (see `reason`).
    Refused,
    /// The outcome cannot be established (e.g. the gateway connection was
    /// lost mid-exchange). It may or may not have been sent.
    Indeterminate,
}

impl GroupState {
    pub fn is_final(self) -> bool {
        !matches!(self, Self::Pending | Self::InProgress)
    }
}

/// The aggregated outcome of one group send. Counts are `None` until the
/// transport reported them — never an invented zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupResult {
    /// Transport-issued id (pass to [`MeshTransport::group_result`]).
    pub id: String,
    pub group: GroupId,
    pub state: GroupState,
    /// The transport's own state name (RouteLoom: `HOST_QUEUED`,
    /// `WAITING_FOR_END_RECEIPT`, `DELIVERED`, `NOT_SENT`, ...).
    pub detail: String,
    /// Transport reason (RouteLoom: `GROUP_COMPLETE`, `GROUP_INCOMPLETE`,
    /// `GROUP_REQUIRES_GATEWAY_SCOPED`, `NO_ADMISSION_REPLY`, ...).
    pub reason: Option<String>,
    /// Devices that accepted the message as members of the group.
    pub delivered: Option<u32>,
    /// Devices reached that are not members of the group.
    pub nonmember: Option<u32>,
    /// Devices that did not confirm.
    pub missing_total: Option<u32>,
    /// Devices known to the gateway that no confirmation accounted for.
    pub unaccounted: Option<u32>,
    /// Up to a transport-defined number of the unconfirmed device ids.
    pub missing: Vec<NodeId>,
    /// `missing` lists fewer ids than `missing_total`.
    pub missing_truncated: bool,
    /// Transport message identity once assigned (RouteLoom:
    /// `session:sequence` hex, as in [`Message::message_id`]).
    pub message_id: Option<String>,
    /// Host UNIX ms the result became final.
    pub settled_ms: Option<u64>,
}

/// Identity of an accepted group send plus the state known when
/// `send_group` returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupHandle {
    pub id: String,
    pub result: GroupResult,
}

/// Opaque, transport-issued identity of an accepted send; query its outcome
/// through the transport's own operation API.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SendHandle {
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub source: NodeId,
    pub payload: Vec<u8>,
    /// Transport message identity (RouteLoom: `session:sequence` hex) —
    /// stable across redelivery, usable for de-duplication.
    pub message_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MembershipKind {
    /// The device became reachable.
    Joined,
    /// The device is no longer reachable (includes loss of the gateway).
    Left,
    /// Still reachable/known, but the link changed (direct neighbor
    /// gained/lost, route moved).
    LinkChanged,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MembershipEvent {
    pub kind: MembershipKind,
    pub node: NodeId,
    /// Transport-specific cause (RouteLoom: `route_up`, `route_down`,
    /// `sync`, `vanished`, `gateway_attached`, `gateway_lost`,
    /// `neighbor_up`, `neighbor_down`, `next_hop`).
    pub reason: String,
    /// Host UNIX ms the transition was observed.
    pub at_ms: u64,
    /// The device's link status right after the transition, when known.
    pub status: Option<LinkStatus>,
}

/// Per-device link status. Every optional field is `None` when the
/// transport has no measurement — never an invented zero.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkStatus {
    pub node: NodeId,
    /// The application can currently reach the device. `false` drives the
    /// "no communication" display.
    pub connected: bool,
    /// Host UNIX ms of the last frame heard directly from the device.
    pub last_heard_ms: Option<u64>,
    /// Last received signal strength of the device's own frames (dBm).
    pub rssi_dbm: Option<i32>,
    /// Smoothed RSSI (dBm).
    pub rssi_avg_dbm: Option<f64>,
    /// Cost of the direct link (lower is better); None when not a direct
    /// neighbor.
    pub link_cost: Option<u32>,
    /// Path cost to the device; None when unreachable.
    pub route_metric: Option<u32>,
    /// Hop count when known (0 = the gateway itself, 1 = direct).
    pub hops: Option<u32>,
    /// Next relay toward the device; None when unreachable.
    pub next_hop: Option<NodeId>,
}

impl LinkStatus {
    /// The status of a device the transport knows nothing about.
    pub fn unknown(node: NodeId) -> Self {
        Self {
            node,
            connected: false,
            last_heard_ms: None,
            rssi_dbm: None,
            rssi_avg_dbm: None,
            link_cost: None,
            route_metric: None,
            hops: None,
            next_hop: None,
        }
    }
}

#[derive(Debug)]
pub enum TransportError {
    /// The local transport endpoint (socket, driver) failed.
    Io(io::Error),
    /// The transport answered with a typed refusal.
    Rejected {
        code: String,
        message: String,
        retryable: bool,
    },
    /// The transport answered something this client cannot interpret.
    Protocol(String),
    /// A stream lost items (slow consumer / buffer overflow). The stream
    /// continues; the application should resynchronize state (e.g. re-read
    /// `links()`).
    Gap(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "transport I/O: {error}"),
            Self::Rejected { code, message, .. } => write!(f, "rejected {code}: {message}"),
            Self::Protocol(detail) => write!(f, "protocol: {detail}"),
            Self::Gap(detail) => write!(f, "stream gap: {detail}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub type MessageStream = Box<dyn Iterator<Item = Result<Message, TransportError>> + Send>;
pub type MembershipStream =
    Box<dyn Iterator<Item = Result<MembershipEvent, TransportError>> + Send>;

/// The four-operation contract. Implementations must be usable from several
/// threads (one receive loop, one membership loop, senders, a status poller).
pub trait MeshTransport: Send + Sync {
    /// Accepts `payload` for `dest`. `Ok` means the transport took
    /// responsibility (queued), not that the device received it.
    fn send(
        &self,
        dest: NodeId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendHandle, TransportError>;

    /// Payloads from devices, starting now. The iterator blocks for the
    /// next item and ends when the transport closes the stream.
    fn receive(&self) -> Result<MessageStream, TransportError>;

    /// Joined / left / link-changed events, starting now.
    fn membership(&self) -> Result<MembershipStream, TransportError>;

    /// Current status of one device ([`LinkStatus::unknown`] when the
    /// transport has never seen it).
    fn link_status(&self, node: NodeId) -> Result<LinkStatus, TransportError>;

    /// Current status of every device the transport knows.
    fn links(&self) -> Result<Vec<LinkStatus>, TransportError>;

    /// Sends `payload` to every device in `group` ([`GROUP_ALL`] = all).
    /// `Ok` means the transport accepted the message (the handle's result
    /// may still be pending); a refusal before transmission is an `Err`.
    fn send_group(
        &self,
        group: GroupId,
        payload: &[u8],
        options: &GroupSendOptions,
    ) -> Result<GroupHandle, TransportError> {
        let _ = (group, payload, options);
        Err(unsupported("send_group"))
    }

    /// The current (or, waiting up to `wait_ms`, the final) outcome of a
    /// group send.
    fn group_result(&self, id: &str, wait_ms: u32) -> Result<GroupResult, TransportError> {
        let _ = (id, wait_ms);
        Err(unsupported("group_result"))
    }
}

fn unsupported(operation: &str) -> TransportError {
    TransportError::Rejected {
        code: "UNSUPPORTED".to_string(),
        message: format!("{operation} is not supported by this transport"),
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::mpsc;
    use std::sync::Mutex;

    /// A stand-in for any other carrier (e.g. Wi-Fi/TCP): proves the trait
    /// carries no RouteLoom specifics and that application logic written
    /// against it is transport-independent.
    #[derive(Default)]
    struct MockTransport {
        sent: Mutex<Vec<(NodeId, Vec<u8>, SendOptions)>>,
        links: Mutex<BTreeMap<NodeId, LinkStatus>>,
        inbound: Mutex<Vec<Message>>,
        events: Mutex<Vec<MembershipEvent>>,
    }

    impl MeshTransport for MockTransport {
        fn send(
            &self,
            dest: NodeId,
            payload: &[u8],
            options: &SendOptions,
        ) -> Result<SendHandle, TransportError> {
            if !self.link_status(dest)?.connected {
                return Err(TransportError::Rejected {
                    code: "NO_ROUTE".into(),
                    message: "device not connected".into(),
                    retryable: true,
                });
            }
            let mut sent = self.sent.lock().unwrap();
            sent.push((dest, payload.to_vec(), options.clone()));
            Ok(SendHandle {
                id: format!("mock-{}", sent.len()),
            })
        }
        fn receive(&self) -> Result<MessageStream, TransportError> {
            let items: Vec<_> = self.inbound.lock().unwrap().drain(..).map(Ok).collect();
            Ok(Box::new(items.into_iter()))
        }
        fn membership(&self) -> Result<MembershipStream, TransportError> {
            let items: Vec<_> = self.events.lock().unwrap().drain(..).map(Ok).collect();
            Ok(Box::new(items.into_iter()))
        }
        fn link_status(&self, node: NodeId) -> Result<LinkStatus, TransportError> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .get(&node)
                .cloned()
                .unwrap_or_else(|| LinkStatus::unknown(node)))
        }
        fn links(&self) -> Result<Vec<LinkStatus>, TransportError> {
            Ok(self.links.lock().unwrap().values().cloned().collect())
        }
    }

    /// KGuard-style consumer: the display board shows a blue status bar
    /// whenever its device is not connected; the admin screen prints "no
    /// communication" with the last-heard time. Written once, generic.
    fn status_bar<T: MeshTransport + ?Sized>(transport: &T, node: NodeId) -> &'static str {
        match transport.link_status(node) {
            Ok(status) if status.connected => "normal",
            _ => "blue",
        }
    }

    fn admin_line<T: MeshTransport + ?Sized>(transport: &T) -> Vec<String> {
        transport
            .links()
            .unwrap()
            .iter()
            .map(|s| {
                if s.connected {
                    format!("{:x}: ok rssi={:?}", s.node, s.rssi_dbm)
                } else {
                    format!(
                        "{:x}: no communication (last heard {:?})",
                        s.node, s.last_heard_ms
                    )
                }
            })
            .collect()
    }

    fn connected(node: NodeId) -> LinkStatus {
        LinkStatus {
            connected: true,
            last_heard_ms: Some(1_000),
            rssi_dbm: Some(-60),
            rssi_avg_dbm: Some(-61.5),
            link_cost: Some(1),
            route_metric: Some(1),
            hops: Some(1),
            next_hop: Some(node),
            ..LinkStatus::unknown(node)
        }
    }

    #[test]
    fn application_logic_is_transport_independent() {
        let mock = MockTransport::default();
        mock.links.lock().unwrap().insert(2, connected(2));
        let mut gone = connected(3);
        gone.connected = false;
        gone.route_metric = None;
        mock.links.lock().unwrap().insert(3, gone);

        // Works through a trait object exactly like a concrete type.
        let dynamic: &dyn MeshTransport = &mock;
        assert_eq!(status_bar(dynamic, 2), "normal");
        assert_eq!(status_bar(dynamic, 3), "blue");
        assert_eq!(status_bar(dynamic, 99), "blue"); // never seen
        assert_eq!(
            admin_line(&mock),
            vec![
                "2: ok rssi=Some(-60)".to_string(),
                "3: no communication (last heard Some(1000))".to_string()
            ]
        );

        let handle = mock.send(2, b"lock", &SendOptions::default()).unwrap();
        assert_eq!(handle.id, "mock-1");
        assert!(matches!(
            mock.send(3, b"lock", &SendOptions::default()),
            Err(TransportError::Rejected {
                retryable: true,
                ..
            })
        ));
        assert_eq!(mock.sent.lock().unwrap()[0].2.delivery, Delivery::Reliable);
    }

    #[test]
    fn streams_are_consumable_from_other_threads() {
        let mock = std::sync::Arc::new(MockTransport::default());
        mock.inbound.lock().unwrap().push(Message {
            source: 2,
            payload: b"door-open".to_vec(),
            message_id: "00000001:0000000000000007".into(),
        });
        mock.events.lock().unwrap().push(MembershipEvent {
            kind: MembershipKind::Left,
            node: 2,
            reason: "route_down".into(),
            at_ms: 5,
            status: Some(LinkStatus::unknown(2)),
        });
        let (tx, rx) = mpsc::channel();
        let transport = std::sync::Arc::clone(&mock);
        std::thread::spawn(move || {
            for message in transport.receive().unwrap() {
                tx.send(format!("msg {:?}", message.unwrap().payload))
                    .unwrap();
            }
            for event in transport.membership().unwrap() {
                let event = event.unwrap();
                tx.send(format!("{:?} {}", event.kind, event.node)).unwrap();
            }
        })
        .join()
        .unwrap();
        let lines: Vec<String> = rx.try_iter().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("Left 2"));
    }

    /// Transports that predate group delivery keep compiling and answer
    /// an explicit UNSUPPORTED — the four-operation contract is unchanged.
    #[test]
    fn group_operations_default_to_unsupported() {
        let mock = MockTransport::default();
        let dynamic: &dyn MeshTransport = &mock;
        for result in [
            dynamic
                .send_group(GROUP_ALL, b"ALARM", &GroupSendOptions::alarm())
                .map(|_| ()),
            dynamic.group_result("x", 0).map(|_| ()),
        ] {
            match result {
                Err(TransportError::Rejected {
                    code, retryable, ..
                }) => assert_eq!((code.as_str(), retryable), ("UNSUPPORTED", false)),
                other => panic!("expected UNSUPPORTED, got {other:?}"),
            }
        }
        let alarm = GroupSendOptions::alarm();
        assert_eq!(alarm.priority, Priority::Urgent);
        assert!(!alarm.ordered);
        assert!(GroupSendOptions::ordered_update().ordered);
        assert!(!GroupState::Pending.is_final() && !GroupState::InProgress.is_final());
        assert!(GroupState::Delivered.is_final() && GroupState::Indeterminate.is_final());
    }

    #[test]
    fn defaults_and_errors_are_explicit() {
        let options = SendOptions::default();
        assert_eq!(
            (options.ttl_ms, options.hop_limit, options.durable),
            (5_000, 10, false)
        );
        let unknown = LinkStatus::unknown(7);
        assert!(
            !unknown.connected && unknown.last_heard_ms.is_none() && unknown.rssi_dbm.is_none()
        );
        let error = TransportError::Rejected {
            code: "NOT_FOUND".into(),
            message: "x".into(),
            retryable: false,
        };
        assert_eq!(error.to_string(), "rejected NOT_FOUND: x");
        let io: TransportError = io::Error::new(io::ErrorKind::NotFound, "sock").into();
        assert!(matches!(io, TransportError::Io(_)));
    }
}
