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
//! `ROUTELOOM_{MESH,OWNER}_PEER_{GW,A,B}` select profile-built peers for
//! each persona in the mixed-profile run.
//! With either missing, every test skips (ignore-equivalent, never
//! a failure); the CI interop job builds both peers and always runs
//! them live. Time is one virtual clock shared by all peers and the
//! authority (`t0` = wall `now_ms` at start).
//!
//! `world`, `peer`, `switch`, `usb_host` and `report` are the harness;
//! `mesh`, `join`, `membership`, `cutover`, `fault`, `boot`, `recovery`,
//! `compat`, `product`, `send` and `device` hold the scenario tests, each
//! registered by its row in `tests/e2e/scenarios.json`.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use super::assignment_table::{Assignment, AssignmentTable};
use routeloom_client::api1::RouteLoomTransport;
use routeloom_client::site::{Role, SiteAdmin};
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

mod boot;
mod compat;
mod consumer;
mod crypto;
mod cutover;
mod daemon;
mod device;
mod end;
mod fault;
mod join;
mod kg;
mod load;
mod membership;
mod mesh;
mod peer;
mod product;
mod recovery;
mod report;
mod send;
mod switch;
mod usb_host;
mod world;

use peer::*;
use switch::*;
use usb_host::*;
use world::*;

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
const ROLE_ENDPOINT: u8 = 1;
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

// C++ `DeliveryState` (types.hpp).
const DELIVERY_DELIVERED: u8 = 7;
// C++ `SessionState` (usb_bridge.hpp): the gateway USB is usable in Active.
const USB_ACTIVE: u8 = 3;
// C++ `CoordinatorMode` (sdkv1_security_coordinator.hpp).
const MODE_ZERO_TOUCH: u8 = 1;
const MODE_MEMBER: u8 = 2;
// C++ `LifecyclePhase` (sdkv1_revocation.hpp).
const PHASE_REMOVING: u8 = 7;
const PHASE_HOLDOFF: u8 = 8;
const PHASE_PREPARED: u8 = 10;

const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

const PHASE_REACHABLE: u8 = 5;
const PHASE_STALE: u8 = 7;
const WIRE_DATA: u8 = 16;
const WIRE_HOP_ACCEPT: u8 = 17;
const WIRE_END_RECEIPT: u8 = 18;
const WIRE_ROUTE_UPDATE: u8 = 32;
const WIRE_PROBE: u8 = 40;
const WIRE_RESULT: u8 = 41;
