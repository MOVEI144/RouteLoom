//! Regenerates protocol/usb-golden/*.json — shared session vectors for the
//! USB device bridge. The C++ harness (tests/cpp/test_usb.cpp) replays the
//! host wire bytes into a real UsbBridge and requires byte-identical device
//! output; the Rust harness (tests/usb_golden.rs) verifies the same files.
//! Run: cargo run -p routeloom-protocol --example gen_usb_golden

use routeloom_protocol::dev_session::*;
use routeloom_protocol::host_ops::*;
use routeloom_protocol::{encode_frame, Frame, FrameKind};
use std::fs;
use std::path::{Path, PathBuf};

const SECRET: &[u8] = b"routeloom-dev-secret";
const HOST_NONCE: u64 = 0x0102_0304_0506_0708;
const DEVICE_NONCE: u64 = 0xa0b0_c0d0_e0f0_0102;
const NODE: u64 = 1;
const BOOT: u64 = 0x0000_00b0_071d_0001;
const NETWORK: u64 = 7;
// Legacy 0x3 plus the host_ops_v1 bit: this golden device speaks HostOps.
const CAPABILITY: u32 = 0x3 | CAP_HOST_OPS_V1;
const DISPATCHER: &[u8; DISPATCHER_ID_SIZE] = b"host-dispatcher1";
const PRINCIPAL: &[u8] = b"host-operator";
const MESH_SESSION: u32 = 7001; // gateway message_session
const PEER_SESSION: u32 = 2002; // node-2 message_session
const PEER_NODE: u64 = 2;
const RX_GRANT_FRAMES: u64 = 8; // device headroom (C++ kRxGrantFrames)
const RX_GRANT_BYTES: u64 = 16384; // device headroom (C++ kRxGrantBytes)
const TX_GRANT_FRAMES: u64 = 16; // host grant to device
const TX_GRANT_BYTES: u64 = 65536;

fn hex(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

struct Step {
    name: &'static str,
    direction: &'static str,
    frame: Frame,
    inner: Vec<u8>,
    note: &'static str,
}

fn write_step(dir: &Path, index: usize, step: &Step) -> std::io::Result<()> {
    let wire = encode_frame(&step.frame).expect("encodable vector frame");
    let text = format!(
        "{{\n  \"name\": \"{}\",\n  \"direction\": \"{}\",\n  \"kind\": {},\n  \"flags\": {},\n  \"session\": {},\n  \"request\": {},\n  \"inner_hex\": \"{}\",\n  \"body_hex\": \"{}\",\n  \"wire_hex\": \"{}\",\n  \"note\": \"{}\"\n}}\n",
        step.name,
        step.direction,
        step.frame.kind as u8,
        step.frame.flags,
        step.frame.session,
        step.frame.request,
        hex(&step.inner),
        hex(&step.frame.body),
        hex(&wire),
        step.note,
    );
    fs::write(dir.join(format!("{:02}_{}.json", index, step.name)), text)
}

fn main() -> std::io::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("protocol/usb-golden");
    let frames_dir = root.join("frames");
    fs::create_dir_all(&frames_dir)?;
    for entry in fs::read_dir(&frames_dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|ext| ext == "json") {
            fs::remove_file(entry.path())?;
        }
    }

    let transcript = Transcript {
        host_nonce: HOST_NONCE,
        device_nonce: DEVICE_NONCE,
        version: 1,
        node: NODE,
        boot: BOOT,
        network: NETWORK,
        capability: CAPABILITY,
        principal: PRINCIPAL.to_vec(),
    };
    let proof = derive_session_proof(SECRET, &transcript.encode().unwrap());
    let session = proof.session_id;

    let mut d2h_counter = 0_u64;
    let mut h2d_counter = 0_u64;
    let mut steps: Vec<Step> = Vec::new();
    let mut d2h = |name, note, kind, flags, request, inner: Vec<u8>| Step {
        name,
        direction: "d2h",
        frame: Frame {
            kind,
            flags,
            session,
            request,
            body: seal_body(
                &proof.key,
                DIRECTION_DEVICE_TO_HOST,
                {
                    let counter = d2h_counter;
                    d2h_counter += 1;
                    counter
                },
                kind,
                flags,
                request,
                &inner,
            ),
        },
        inner,
        note,
    };
    let mut h2d = |name, note, kind, flags, request, inner: Vec<u8>| Step {
        name,
        direction: "h2d",
        frame: Frame {
            kind,
            flags,
            session,
            request,
            body: seal_body(
                &proof.key,
                DIRECTION_HOST_TO_DEVICE,
                {
                    let counter = h2d_counter;
                    h2d_counter += 1;
                    counter
                },
                kind,
                flags,
                request,
                &inner,
            ),
        },
        inner,
        note,
    };

    // 1-2: HELLO / HELLO_ACK (unauthenticated, session=0).
    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&HOST_NONCE.to_be_bytes());
    hello_body.push(1); // min version
    hello_body.push(1); // max version
    hello_body.push(PRINCIPAL.len() as u8);
    hello_body.extend_from_slice(PRINCIPAL);
    steps.push(Step {
        name: "hello",
        direction: "h2d",
        frame: Frame {
            kind: FrameKind::Hello,
            flags: 0,
            session: 0,
            request: 100,
            body: hello_body.clone(),
        },
        inner: hello_body,
        note: "host opens: nonce, version range, principal",
    });

    let mut ack_body = Vec::new();
    ack_body.extend_from_slice(&DEVICE_NONCE.to_be_bytes());
    ack_body.push(1);
    ack_body.extend_from_slice(&NODE.to_be_bytes());
    ack_body.extend_from_slice(&BOOT.to_be_bytes());
    ack_body.extend_from_slice(&NETWORK.to_be_bytes());
    ack_body.extend_from_slice(&CAPABILITY.to_be_bytes());
    ack_body.extend_from_slice(&proof.hello_tag);
    steps.push(Step {
        name: "hello_ack",
        direction: "d2h",
        frame: Frame {
            kind: FrameKind::HelloAck,
            flags: 0,
            session: 0,
            request: 100,
            body: ack_body.clone(),
        },
        inner: ack_body,
        note: "device identity + hello tag proves the shared secret",
    });

    // 3-4: AUTH / AUTH_OK.
    steps.push(Step {
        name: "auth",
        direction: "h2d",
        frame: Frame {
            kind: FrameKind::Hello,
            flags: FLAG_AUTH,
            session: 0,
            request: 101,
            body: proof.auth_tag.to_vec(),
        },
        inner: proof.auth_tag.to_vec(),
        note: "host proves the shared secret over the transcript",
    });
    let mut auth_ok_body = proof.auth_ok_tag.to_vec();
    auth_ok_body.extend_from_slice(&session.to_be_bytes());
    steps.push(Step {
        name: "auth_ok",
        direction: "d2h",
        frame: Frame {
            kind: FrameKind::HelloAck,
            flags: FLAG_AUTH,
            session: 0,
            request: 0,
            body: auth_ok_body.clone(),
        },
        inner: auth_ok_body,
        note: "device confirms; session id binds the transcript",
    });

    // 5: initial device grant for host->device traffic (first protected frame).
    let mut rx_grant_inner = vec![CREDIT_GRANT];
    rx_grant_inner.extend_from_slice(&RX_GRANT_FRAMES.to_be_bytes());
    rx_grant_inner.extend_from_slice(&RX_GRANT_BYTES.to_be_bytes());
    steps.push(d2h(
        "rx_grant",
        "initial cumulative grant for host->device sends",
        FrameKind::Credit,
        0,
        0,
        rx_grant_inner,
    ));

    // 6: host grants device->host sends.
    let mut tx_grant_inner = vec![CREDIT_GRANT];
    tx_grant_inner.extend_from_slice(&TX_GRANT_FRAMES.to_be_bytes());
    tx_grant_inner.extend_from_slice(&TX_GRANT_BYTES.to_be_bytes());
    steps.push(h2d(
        "tx_grant",
        "host grants device->host data sends",
        FrameKind::Credit,
        0,
        102,
        tx_grant_inner,
    ));

    // 7: host command into the mesh.
    // inner = idempotency_key || destination || payload.
    let payload = b"mesh-down";
    let mut data_inner = Vec::new();
    data_inner.extend_from_slice(&0x00A1_1CE7_u64.to_be_bytes());
    data_inner.extend_from_slice(&PEER_NODE.to_be_bytes());
    data_inner.extend_from_slice(payload);
    steps.push(h2d(
        "data_to_mesh",
        "host command: send 9-byte payload to node 2",
        FrameKind::DataToMesh,
        0,
        103,
        data_inner.clone(),
    ));

    // Tracks host->device data consumption for grant topups: each data
    // frame consumes 1 frame + its full decoded protected length
    // (30 header/CRC + 24 counter/tag + inner), and the device re-grants
    // consumed + headroom.
    let mut consumed_frames = 0_u64;
    let mut consumed_bytes = 0_u64;
    let mut note_consumed = |inner_len: usize| {
        consumed_frames += 1;
        consumed_bytes += (30 + 24 + inner_len) as u64;
        let mut topup_inner = vec![CREDIT_GRANT];
        topup_inner.extend_from_slice(&(consumed_frames + RX_GRANT_FRAMES).to_be_bytes());
        topup_inner.extend_from_slice(&(consumed_bytes + RX_GRANT_BYTES).to_be_bytes());
        topup_inner
    };

    // 8: device advances the cumulative rx grant after releasing the buffer.
    let topup_inner = note_consumed(data_inner.len());
    steps.push(d2h(
        "rx_grant_topup",
        "grant advances as the reserved buffer is released",
        FrameKind::Credit,
        0,
        0,
        topup_inner,
    ));

    // 9-10: delivery events for the accepted mesh send.
    let delivery = |state: u8, reason: &[u8]| {
        let mut inner = Vec::new();
        inner.extend_from_slice(&103_u64.to_be_bytes());
        inner.extend_from_slice(&MESH_SESSION.to_be_bytes());
        inner.extend_from_slice(&1_u64.to_be_bytes());
        inner.push(state);
        inner.push(reason.len() as u8);
        inner.extend_from_slice(reason);
        inner
    };
    steps.push(d2h(
        "delivery_accepted",
        "MeshNode accepted the command (COMMAND_ACCEPTED)",
        FrameKind::DeliveryEvent,
        0,
        103,
        delivery(1, b"TX_ACCEPTED"),
    ));
    steps.push(d2h(
        "delivery_queued",
        "origin delivery queued for first transmission",
        FrameKind::DeliveryEvent,
        0,
        103,
        delivery(3, b"QUEUED"),
    ));

    // Host-ops scenario (CAP-I2): SKIP two holes, retire the terminal
    // prefix, SUBMIT into the window, QUERY the live and retired positions,
    // and take a time sample. Each host->device data frame is followed by
    // the device's rx-grant topup (CONTROL drains first) and then the
    // typed response. Request ids 200+ keep clear of the session scenario.
    //
    // The C++ replay feeds host frames at now = file_index * 200ms, so the
    // SUBMIT deadline and the expected TIME_SAMPLE device_time derive from
    // the step position: `steps.len()` is the 0-based index of the frame
    // being appended.
    let lease = BootLease::derive(BOOT, NODE);
    let mut canonical = vec![0_u8; 26];
    canonical[0] = 1; // schema
    canonical[4] = NETWORK as u8;
    canonical[5] = 0; // node destination
    canonical[13] = PEER_NODE as u8;
    canonical[14] = 1; // RELIABLE
    canonical[15] = 1; // NORMAL
    canonical[17] = 1; // HOST_DURABLE
    canonical[20] = 0x13; // ttl 5000
    canonical[21] = 0x88;
    canonical[22] = 10; // hop limit
    canonical.extend_from_slice(b"gw-submit");
    canonical[25] = 9; // payload length
    let mut submit_hash = [0_u8; CANONICAL_HASH_SIZE];
    for (i, byte) in submit_hash.iter_mut().enumerate() {
        *byte = 0x10 + i as u8; // opaque to the device; host SHA-256 in production
    }
    let mut operation_id = [0_u8; OPERATION_ID_SIZE];
    for (i, byte) in operation_id[..16].iter_mut().enumerate() {
        *byte = 0xA0 + i as u8; // store lineage
    }
    operation_id[23] = 1; // operation seq
    let mut next_request = 200_u64;

    for seq in [1_u64, 2] {
        let inner = encode_lane_request(
            SUB_SKIP,
            &LaneRequest {
                lease,
                dispatcher: *DISPATCHER,
                seq,
            },
        );
        steps.push(h2d(
            if seq == 1 { "skip_hole1" } else { "skip_hole2" },
            "host certifies a never-submitted hole as skipped",
            FrameKind::HostOps,
            0,
            next_request,
            inner.clone(),
        ));
        let topup = note_consumed(inner.len());
        steps.push(d2h(
            if seq == 1 {
                "skip_hole1_grant"
            } else {
                "skip_hole2_grant"
            },
            "rx grant advances past the host_ops request",
            FrameKind::Credit,
            0,
            0,
            topup,
        ));
        steps.push(d2h(
            if seq == 1 {
                "skip_hole1_receipt"
            } else {
                "skip_hole2_receipt"
            },
            "hole filled with a terminal Skipped record",
            FrameKind::HostOps,
            0,
            next_request,
            encode_receipt(&Receipt {
                sub: SUB_SKIP,
                result: HostOpsResult::Ok,
                state: SlotState::Skipped,
                lease,
                dispatch_seq: seq,
                hash: [0; CANONICAL_HASH_SIZE],
                msg_session: 0,
                msg_seq: 0,
                msg_valid: false,
                evidence: Evidence::None,
            }),
        ));
        next_request += 1;
    }

    let retire_inner = encode_lane_request(
        SUB_RETIRE_THROUGH,
        &LaneRequest {
            lease,
            dispatcher: *DISPATCHER,
            seq: 2,
        },
    );
    steps.push(h2d(
        "retire_prefix",
        "host retires the terminal 1..2 prefix",
        FrameKind::HostOps,
        0,
        next_request,
        retire_inner.clone(),
    ));
    let topup = note_consumed(retire_inner.len());
    steps.push(d2h(
        "retire_prefix_grant",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        0,
        topup,
    ));
    steps.push(d2h(
        "retire_prefix_resp",
        "floor advanced to 2",
        FrameKind::HostOps,
        0,
        next_request,
        encode_retire_response(&RetireResponse {
            result: HostOpsResult::Ok,
            lease,
            retired_through: 2,
        }),
    ));
    next_request += 1;

    // SUBMIT fed at now = index*200; the deadline leaves 5000ms of life.
    let submit_now = steps.len() as u64 * 200;
    let submit_inner = encode_submit(&SubmitRequest {
        lease,
        dispatcher: *DISPATCHER,
        dispatch_seq: 3,
        operation_id,
        canonical_hash: submit_hash,
        device_deadline: submit_now + 5000,
        canonical: canonical.clone(),
    })
    .expect("encodable submit vector");
    steps.push(h2d(
        "submit_seq3",
        "host submits dispatch seq 3 (9-byte mesh payload)",
        FrameKind::HostOps,
        0,
        next_request,
        submit_inner.clone(),
    ));
    let topup = note_consumed(submit_inner.len());
    steps.push(d2h(
        "submit_seq3_grant",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        0,
        topup,
    ));
    // The legacy data_to_mesh send took message seq 1, so this SUBMIT lands
    // on message seq 2; the C++ bridge mesh-sends synchronously at admission.
    steps.push(d2h(
        "submit_seq3_receipt",
        "admitted and mesh-sent; stable MessageKey returned",
        FrameKind::HostOps,
        0,
        next_request,
        encode_receipt(&Receipt {
            sub: SUB_SUBMIT,
            result: HostOpsResult::Ok,
            state: SlotState::Sent,
            lease,
            dispatch_seq: 3,
            hash: submit_hash,
            msg_session: MESH_SESSION,
            msg_seq: 2,
            msg_valid: true,
            evidence: Evidence::GatewayAccepted,
        }),
    ));
    next_request += 1;

    let query_inner = encode_lane_request(
        SUB_QUERY_DISPATCH,
        &LaneRequest {
            lease,
            dispatcher: *DISPATCHER,
            seq: 3,
        },
    );
    steps.push(h2d(
        "query_seq3",
        "host reads back the live record",
        FrameKind::HostOps,
        0,
        next_request,
        query_inner.clone(),
    ));
    let topup = note_consumed(query_inner.len());
    steps.push(d2h(
        "query_seq3_grant",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        0,
        topup,
    ));
    steps.push(d2h(
        "query_seq3_resp",
        "record still Sent (no mesh poll ran in between)",
        FrameKind::HostOps,
        0,
        next_request,
        encode_query_response(&QueryResponse {
            result: HostOpsResult::Ok,
            state: SlotState::Sent,
            lease,
            dispatch_seq: 3,
            hash: submit_hash,
            operation_id,
            msg_session: MESH_SESSION,
            msg_seq: 2,
            msg_valid: true,
            evidence: Evidence::GatewayAccepted,
        }),
    ));
    next_request += 1;

    let query_old_inner = encode_lane_request(
        SUB_QUERY_DISPATCH,
        &LaneRequest {
            lease,
            dispatcher: *DISPATCHER,
            seq: 1,
        },
    );
    steps.push(h2d(
        "query_retired",
        "host queries the retired seq 1",
        FrameKind::HostOps,
        0,
        next_request,
        query_old_inner.clone(),
    ));
    let topup = note_consumed(query_old_inner.len());
    steps.push(d2h(
        "query_retired_grant",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        0,
        topup,
    ));
    steps.push(d2h(
        "query_retired_resp",
        "retired positions answer Retired with zeroed record fields",
        FrameKind::HostOps,
        0,
        next_request,
        encode_query_response(&QueryResponse {
            result: HostOpsResult::Retired,
            state: SlotState::Empty,
            lease,
            dispatch_seq: 1,
            hash: [0; CANONICAL_HASH_SIZE],
            operation_id: [0; OPERATION_ID_SIZE],
            msg_session: 0,
            msg_seq: 0,
            msg_valid: false,
            evidence: Evidence::None,
        }),
    ));
    next_request += 1;

    let sample_now = steps.len() as u64 * 200;
    let sample_inner = encode_time_sample_request(&TimeSampleRequest {
        lease,
        nonce: 0x5A5A,
    });
    steps.push(h2d(
        "time_sample",
        "host requests a bound device clock sample",
        FrameKind::HostOps,
        0,
        next_request,
        sample_inner.clone(),
    ));
    let topup = note_consumed(sample_inner.len());
    steps.push(d2h(
        "time_sample_grant",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        0,
        topup,
    ));
    steps.push(d2h(
        "time_sample_resp",
        "device time sampled at the fed instant",
        FrameKind::HostOps,
        0,
        next_request,
        encode_time_sample_response(&TimeSampleResponse {
            result: HostOpsResult::Ok,
            lease,
            nonce: 0x5A5A,
            device_time: sample_now,
        }),
    ));

    // 11: a mesh message arriving at the gateway becomes DataFromMesh.
    let mesh_payload = b"mesh-up!";
    let mut from_mesh_inner = Vec::new();
    from_mesh_inner.extend_from_slice(&PEER_NODE.to_be_bytes());
    from_mesh_inner.extend_from_slice(&PEER_SESSION.to_be_bytes());
    from_mesh_inner.extend_from_slice(&1_u64.to_be_bytes());
    from_mesh_inner.extend_from_slice(mesh_payload);
    steps.push(d2h(
        "data_from_mesh",
        "node 2 delivered an 8-byte application payload",
        FrameKind::DataFromMesh,
        0,
        0,
        from_mesh_inner,
    ));

    // 12-13: keepalive exchange (CONTROL reservation traffic).
    steps.push(h2d(
        "keepalive",
        "host keepalive inside the session",
        FrameKind::KeepAlive,
        0,
        104,
        Vec::new(),
    ));
    steps.push(d2h(
        "keepalive_ack",
        "device keepalive answer",
        FrameKind::KeepAlive,
        0,
        104,
        Vec::new(),
    ));

    // 14: host closes; the device drains and ends the session silently.
    steps.push(h2d(
        "close",
        "host requests session close; device drains",
        FrameKind::Credit,
        0,
        105,
        vec![CREDIT_CLOSE],
    ));

    for (index, step) in steps.iter().enumerate() {
        write_step(&frames_dir, index + 1, step)?;
    }

    let session_json = format!(
        "{{\n  \"name\": \"dev-session-basic\",\n  \"secret_hex\": \"{}\",\n  \"host_nonce\": {},\n  \"device_nonce\": {},\n  \"version\": 1,\n  \"node\": {},\n  \"boot\": {},\n  \"network\": {},\n  \"capability\": {},\n  \"principal\": \"{}\",\n  \"session_id\": {},\n  \"mesh_session\": {},\n  \"peer_node\": {},\n  \"peer_session\": {},\n  \"rx_grant_frames\": {},\n  \"rx_grant_bytes\": {},\n  \"tx_grant_frames\": {},\n  \"tx_grant_bytes\": {},\n  \"hello_tag_hex\": \"{}\",\n  \"auth_tag_hex\": \"{}\",\n  \"auth_ok_tag_hex\": \"{}\",\n  \"session_key_hex\": \"{}\"\n}}\n",
        hex(SECRET),
        HOST_NONCE,
        DEVICE_NONCE,
        NODE,
        BOOT,
        NETWORK,
        CAPABILITY,
        std::str::from_utf8(PRINCIPAL).expect("ascii principal"),
        session,
        MESH_SESSION,
        PEER_NODE,
        PEER_SESSION,
        RX_GRANT_FRAMES,
        RX_GRANT_BYTES,
        TX_GRANT_FRAMES,
        TX_GRANT_BYTES,
        hex(&proof.hello_tag),
        hex(&proof.auth_tag),
        hex(&proof.auth_ok_tag),
        hex(&proof.key),
    );
    fs::write(root.join("session.json"), session_json)?;
    println!("wrote {} steps to {}", steps.len(), frames_dir.display());
    node_status_scenario(&root.join("node-status"))?;
    group_ops_scenario(&root.join("group-ops"))?;
    join_relay_scenario(&root.join("join-relay"))?;
    Ok(())
}

/// Minimal session writer for the node_status_v1 scenario: tracks both
/// direction counters so steps can be appended in wire order.
struct SessionSteps {
    session: u64,
    key: [u8; 16],
    d2h_counter: u64,
    h2d_counter: u64,
    steps: Vec<Step>,
}

impl SessionSteps {
    fn sealed(
        &mut self,
        name: &'static str,
        direction: &'static str,
        note: &'static str,
        kind: FrameKind,
        request: u64,
        inner: Vec<u8>,
    ) {
        let (dir, counter) = if direction == "h2d" {
            let counter = self.h2d_counter;
            self.h2d_counter += 1;
            (DIRECTION_HOST_TO_DEVICE, counter)
        } else {
            let counter = self.d2h_counter;
            self.d2h_counter += 1;
            (DIRECTION_DEVICE_TO_HOST, counter)
        };
        self.steps.push(Step {
            name,
            direction,
            frame: Frame {
                kind,
                flags: 0,
                session: self.session,
                request,
                body: seal_body(&self.key, dir, counter, kind, 0, request, &inner),
            },
            inner,
            note,
        });
    }
}

/// protocol/usb-golden/node-status: the node_status_v1 HostOps family on a
/// device advertising CAP_NODE_STATUS_V1. The C++ replay (test_usb.cpp)
/// drives a two-node mesh (gateway 1 with admitted neighbor 2, link cost 1,
/// no RF observed yet) and removes neighbor 2 just before the event steps.
/// Scenario: SUBSCRIBE query -> first page (node 2 direct) -> the monitor
/// reports NeighborDown + RouteDown -> a resync query shows the departed
/// neighbor record and the event sequence the device reached.
fn node_status_scenario(root: &Path) -> std::io::Result<()> {
    use routeloom_protocol::node_status as ns;

    const CAPABILITY_NS: u32 = 0x3 | CAP_HOST_OPS_V1 | ns::CAP_NODE_STATUS_V1;
    let frames_dir = prepare_frames_dir(root)?;
    let (mut w, proof) = begin_session(
        CAPABILITY_NS,
        "capability advertises node_status_v1 (bit 6)",
    );

    // Node 2 as the gateway sees it right after admission: active neighbor,
    // direct route at the nominal link cost 1, no RF observation yet.
    let admitted = ns::NodeStatusEntry {
        node: PEER_NODE,
        flags: ns::FLAG_NEIGHBOR | ns::FLAG_NEIGHBOR_ACTIVE | ns::FLAG_REACHABLE | ns::FLAG_DIRECT,
        rssi_last_dbm: 0,
        rssi_ewma_q8_8: 0,
        link_cost: 1,
        route_metric: 1,
        next_hop: PEER_NODE,
        heard_age_ms: 0,
    };
    // After remove_neighbor(2): the departed record stays listable, the
    // route is gone.
    let departed = ns::NodeStatusEntry {
        node: PEER_NODE,
        flags: ns::FLAG_NEIGHBOR,
        link_cost: ns::INFINITE_METRIC,
        route_metric: ns::INFINITE_METRIC,
        next_hop: 0,
        ..admitted
    };

    let mut topup = rx_topup();

    let subscribe = ns::encode_node_status_query(&ns::NodeStatusQuery {
        after: 0,
        max_entries: ns::PAGE_MAX as u8,
        flags: ns::QUERY_SUBSCRIBE,
    })
    .expect("valid query");
    w.sealed(
        "node_status_subscribe",
        "h2d",
        "host pages from the start and arms the event stream",
        FrameKind::HostOps,
        300,
        subscribe.clone(),
    );
    w.sealed(
        "node_status_subscribe_grant",
        "d2h",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        topup(subscribe.len()),
    );
    w.sealed(
        "node_status_first_page",
        "d2h",
        "one node: neighbor 2, direct, link cost 1; events armed",
        FrameKind::HostOps,
        300,
        ns::encode_node_status_page(&ns::NodeStatusPage {
            result: ConfigOpsResult::Ok as u16,
            flags: ns::PAGE_ARMED,
            next_after: PEER_NODE,
            event_seq: 0,
            entries: vec![admitted],
        })
        .expect("valid page"),
    );
    w.sealed(
        "node_event_neighbor_down",
        "d2h",
        "neighbor 2 removed: link-level leave (unsolicited, request 0)",
        FrameKind::HostOps,
        0,
        ns::encode_node_event(&ns::NodeEvent {
            sequence: 1,
            kind: ns::NodeEventKind::NeighborDown,
            status: departed,
        })
        .expect("valid event"),
    );
    w.sealed(
        "node_event_route_down",
        "d2h",
        "no route to node 2 remains: node left",
        FrameKind::HostOps,
        0,
        ns::encode_node_event(&ns::NodeEvent {
            sequence: 2,
            kind: ns::NodeEventKind::RouteDown,
            status: departed,
        })
        .expect("valid event"),
    );
    let resync = ns::encode_node_status_query(&ns::NodeStatusQuery {
        after: 0,
        max_entries: ns::PAGE_MAX as u8,
        flags: 0,
    })
    .expect("valid query");
    w.sealed(
        "node_status_resync",
        "h2d",
        "host re-pages without re-arming",
        FrameKind::HostOps,
        301,
        resync.clone(),
    );
    w.sealed(
        "node_status_resync_grant",
        "d2h",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        topup(resync.len()),
    );
    w.sealed(
        "node_status_resync_page",
        "d2h",
        "departed record listed; event_seq reports the 2 issued events",
        FrameKind::HostOps,
        301,
        ns::encode_node_status_page(&ns::NodeStatusPage {
            result: ConfigOpsResult::Ok as u16,
            flags: ns::PAGE_ARMED,
            next_after: PEER_NODE,
            event_seq: 2,
            entries: vec![departed],
        })
        .expect("valid page"),
    );
    w.sealed(
        "close",
        "h2d",
        "host requests session close; device drains",
        FrameKind::Credit,
        302,
        vec![CREDIT_CLOSE],
    );

    finish_session(root, &frames_dir, "node-status", CAPABILITY_NS, &proof, &w)
}

/// Clears (or creates) `<root>/frames` so a regeneration never keeps a
/// renamed step.
fn prepare_frames_dir(root: &Path) -> std::io::Result<PathBuf> {
    let frames_dir = root.join("frames");
    fs::create_dir_all(&frames_dir)?;
    for entry in fs::read_dir(&frames_dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|ext| ext == "json") {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(frames_dir)
}

fn credit_grant(frames: u64, bytes: u64) -> Vec<u8> {
    let mut inner = vec![CREDIT_GRANT];
    inner.extend_from_slice(&frames.to_be_bytes());
    inner.extend_from_slice(&bytes.to_be_bytes());
    inner
}

/// The device's cumulative rx grant after each consumed host_ops request
/// (one frame plus its encoded size: 30 B header/CRC + 24 B seal + inner).
fn rx_topup() -> impl FnMut(usize) -> Vec<u8> {
    let mut consumed_frames = 0_u64;
    let mut consumed_bytes = 0_u64;
    move |inner_len: usize| {
        consumed_frames += 1;
        consumed_bytes += (30 + 24 + inner_len) as u64;
        credit_grant(
            consumed_frames + RX_GRANT_FRAMES,
            consumed_bytes + RX_GRANT_BYTES,
        )
    }
}

/// Hello/HelloAck/auth/auth_ok plus both initial credit grants for a device
/// advertising `capability` — the common opening of every scenario session.
fn begin_session(capability: u32, ack_note: &'static str) -> (SessionSteps, SessionProof) {
    let transcript = Transcript {
        host_nonce: HOST_NONCE,
        device_nonce: DEVICE_NONCE,
        version: 1,
        node: NODE,
        boot: BOOT,
        network: NETWORK,
        capability,
        principal: PRINCIPAL.to_vec(),
    };
    let proof = derive_session_proof(SECRET, &transcript.encode().unwrap());
    let mut w = SessionSteps {
        session: proof.session_id,
        key: proof.key,
        d2h_counter: 0,
        h2d_counter: 0,
        steps: Vec::new(),
    };

    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&HOST_NONCE.to_be_bytes());
    hello_body.extend_from_slice(&[1, 1, PRINCIPAL.len() as u8]);
    hello_body.extend_from_slice(PRINCIPAL);
    w.steps.push(Step {
        name: "hello",
        direction: "h2d",
        frame: Frame {
            kind: FrameKind::Hello,
            flags: 0,
            session: 0,
            request: 100,
            body: hello_body.clone(),
        },
        inner: hello_body,
        note: "host opens: nonce, version range, principal",
    });
    let mut ack_body = Vec::new();
    ack_body.extend_from_slice(&DEVICE_NONCE.to_be_bytes());
    ack_body.push(1);
    ack_body.extend_from_slice(&NODE.to_be_bytes());
    ack_body.extend_from_slice(&BOOT.to_be_bytes());
    ack_body.extend_from_slice(&NETWORK.to_be_bytes());
    ack_body.extend_from_slice(&capability.to_be_bytes());
    ack_body.extend_from_slice(&proof.hello_tag);
    w.steps.push(Step {
        name: "hello_ack",
        direction: "d2h",
        frame: Frame {
            kind: FrameKind::HelloAck,
            flags: 0,
            session: 0,
            request: 100,
            body: ack_body.clone(),
        },
        inner: ack_body,
        note: ack_note,
    });
    w.steps.push(Step {
        name: "auth",
        direction: "h2d",
        frame: Frame {
            kind: FrameKind::Hello,
            flags: FLAG_AUTH,
            session: 0,
            request: 101,
            body: proof.auth_tag.to_vec(),
        },
        inner: proof.auth_tag.to_vec(),
        note: "host proves the shared secret over the transcript",
    });
    let mut auth_ok_body = proof.auth_ok_tag.to_vec();
    auth_ok_body.extend_from_slice(&proof.session_id.to_be_bytes());
    w.steps.push(Step {
        name: "auth_ok",
        direction: "d2h",
        frame: Frame {
            kind: FrameKind::HelloAck,
            flags: FLAG_AUTH,
            session: 0,
            request: 0,
            body: auth_ok_body.clone(),
        },
        inner: auth_ok_body,
        note: "device confirms; session id binds the transcript",
    });
    w.sealed(
        "rx_grant",
        "d2h",
        "initial cumulative grant for host->device sends",
        FrameKind::Credit,
        0,
        credit_grant(RX_GRANT_FRAMES, RX_GRANT_BYTES),
    );
    w.sealed(
        "tx_grant",
        "h2d",
        "host grants device->host data sends",
        FrameKind::Credit,
        102,
        credit_grant(TX_GRANT_FRAMES, TX_GRANT_BYTES),
    );
    (w, proof)
}

/// Writes the step files and the scenario's session.json.
fn finish_session(
    root: &Path,
    frames_dir: &Path,
    name: &str,
    capability: u32,
    proof: &SessionProof,
    w: &SessionSteps,
) -> std::io::Result<()> {
    for (index, step) in w.steps.iter().enumerate() {
        write_step(frames_dir, index + 1, step)?;
    }
    let session_json = format!(
        "{{\n  \"name\": \"{}\",\n  \"secret_hex\": \"{}\",\n  \"host_nonce\": {},\n  \"device_nonce\": {},\n  \"version\": 1,\n  \"node\": {},\n  \"boot\": {},\n  \"network\": {},\n  \"capability\": {},\n  \"principal\": \"{}\",\n  \"session_id\": {},\n  \"peer_node\": {},\n  \"hello_tag_hex\": \"{}\",\n  \"auth_tag_hex\": \"{}\",\n  \"auth_ok_tag_hex\": \"{}\",\n  \"session_key_hex\": \"{}\"\n}}\n",
        name,
        hex(SECRET),
        HOST_NONCE,
        DEVICE_NONCE,
        NODE,
        BOOT,
        NETWORK,
        capability,
        std::str::from_utf8(PRINCIPAL).expect("ascii principal"),
        proof.session_id,
        PEER_NODE,
        hex(&proof.hello_tag),
        hex(&proof.auth_tag),
        hex(&proof.auth_ok_tag),
        hex(&proof.key),
    );
    fs::write(root.join("session.json"), session_json)?;
    println!("wrote {} steps to {}", w.steps.len(), frames_dir.display());
    Ok(())
}

/// protocol/usb-golden/group-ops: the group_delivery_v1 HostOps family on a
/// device advertising CAP_GROUP_DELIVERY_V1. The C++ replay (test_usb.cpp)
/// drives a two-node gateway-scoped mesh (gateway 1 = the bridge node, node
/// 2 its tree child) and pumps the mesh right before the FINAL status.
/// Scenario: GROUP_SEND ALL (Urgent "PUMP3 OVERTEMP") -> immediate status
/// (round pending) -> FINAL status under the same request id (1 member
/// reached, 1 round) -> GROUP_QUERY re-reads the settled summary.
fn group_ops_scenario(root: &Path) -> std::io::Result<()> {
    use routeloom_protocol::group_ops as go;

    const CAPABILITY_GROUP: u32 = 0x3 | CAP_HOST_OPS_V1 | go::CAP_GROUP_DELIVERY_V1;
    // DeliveryState::WaitingForEndReceipt: a round is in flight.
    const STATE_ROUND_PENDING: u8 = 6;
    let frames_dir = prepare_frames_dir(root)?;
    let (mut w, proof) = begin_session(
        CAPABILITY_GROUP,
        "capability advertises group_delivery_v1 (bit 7)",
    );
    let mut topup = rx_topup();

    let sequence = go::GROUP_SEQUENCE_FLAG | 1;
    let send = go::encode_group_send(&go::GroupSend {
        group: go::GROUP_ALL,
        priority: 3,
        ordered: false,
        lifetime_ms: 5000,
        hop_limit: 10,
        data: b"PUMP3 OVERTEMP".to_vec(),
    })
    .expect("valid send");
    w.sealed(
        "group_send",
        "h2d",
        "host asks the gateway to send an Urgent alarm to ALL",
        FrameKind::HostOps,
        400,
        send.clone(),
    );
    w.sealed(
        "group_send_grant",
        "d2h",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        topup(send.len()),
    );
    w.sealed(
        "group_status_admitted",
        "d2h",
        "admitted: group stream 1, first round in flight, not FINAL",
        FrameKind::HostOps,
        400,
        go::encode_group_status(&go::GroupStatus {
            result: ConfigOpsResult::Ok as u16,
            session: MESH_SESSION,
            sequence,
            group: go::GROUP_ALL,
            state: STATE_ROUND_PENDING,
            reason: "GROUP_ROUND_PENDING".to_string(),
            ..go::GroupStatus::default()
        })
        .expect("valid status"),
    );
    let settled = go::GroupStatus {
        result: ConfigOpsResult::Ok as u16,
        session: MESH_SESSION,
        sequence,
        group: go::GROUP_ALL,
        state: go::STATE_DELIVERED,
        rounds: 1,
        delivered: 1,
        reason: "GROUP_COMPLETE".to_string(),
        ..go::GroupStatus::default()
    };
    w.sealed(
        "group_status_final",
        "d2h",
        "FINAL under the send's request id: node 2 confirmed in round 1",
        FrameKind::HostOps,
        400,
        go::encode_group_status(&settled).expect("valid status"),
    );
    let query = go::encode_group_query(&go::GroupQuery {
        session: MESH_SESSION,
        sequence,
    })
    .expect("valid query");
    w.sealed(
        "group_query",
        "h2d",
        "host re-reads the summary by MessageId",
        FrameKind::HostOps,
        401,
        query.clone(),
    );
    w.sealed(
        "group_query_grant",
        "d2h",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        topup(query.len()),
    );
    w.sealed(
        "group_query_status",
        "d2h",
        "the settled summary, FINAL",
        FrameKind::HostOps,
        401,
        go::encode_group_status(&settled).expect("valid status"),
    );
    w.sealed(
        "close",
        "h2d",
        "host requests session close; device drains",
        FrameKind::Credit,
        402,
        vec![CREDIT_CLOSE],
    );
    finish_session(root, &frames_dir, "group-ops", CAPABILITY_GROUP, &proof, &w)
}

/// Deterministic opaque EDHOC message bytes (the relay never parses them).
fn join_message(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i as u8).wrapping_mul(31)))
        .collect()
}

/// protocol/usb-golden/join-relay: the join_relay_v1 HostOps family (SDK v1
/// zero-touch join, docs/design/sdk-v1/02 §7.2/§7.4) on a gateway (node 1)
/// advertising CAP_JOIN_RELAY_V1, with member proxy 2 three hops away. The
/// C++ replay (test_usb.cpp) attaches a JoinRelayGateway to the bridge and
/// injects the proxy's Wire relay frames right before each device step.
/// Scenario: m1 up (single Wire frame) -> host sends m2 down (chunked to the
/// proxy) -> Ok -> m3 up (4 Wire chunks reassembled) -> host sends the final
/// m4 -> Ok -> host aborts the finished relay -> Invalid (not known any
/// more) -> the proxy aborts a second relay -> unsolicited 0x62.
fn join_relay_scenario(root: &Path) -> std::io::Result<()> {
    use routeloom_protocol::join_relay as jr;

    const CAPABILITY_JR: u32 = 0x3 | CAP_HOST_OPS_V1 | jr::CAP_JOIN_RELAY_V1;
    const RELAY_ID: u32 = 0x7E57_AB1E;
    const HOPS: u8 = 3;
    const JOINER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x12, 0x34];
    let frames_dir = prepare_frames_dir(root)?;
    let (mut w, proof) =
        begin_session(CAPABILITY_JR, "capability advertises join_relay_v1 (bit 8)");
    let mut topup = rx_topup();

    let header = |dir, step, state, rssi| jr::RelayHeader {
        dir,
        relay_id: RELAY_ID,
        proxy: PEER_NODE,
        joiner_mac: JOINER_MAC,
        phase: jr::PHASE_EDHOC,
        step,
        state,
        joiner_rssi_dbm: rssi,
    };
    let object = |header: jr::RelayHeader, message: Vec<u8>| {
        jr::RelayObject {
            header,
            body: jr::RelayBody::Message(message),
        }
        .encode()
        .expect("valid relay object")
    };
    let up = |object: Vec<u8>| {
        jr::encode_join_relay_up(&jr::JoinRelayUp {
            gateway: NODE,
            from_proxy: PEER_NODE,
            hops: HOPS,
            object,
        })
        .expect("valid up")
    };
    let result = |result, relay_id| {
        jr::encode_join_relay_result(&jr::JoinRelayResult {
            result,
            proxy: PEER_NODE,
            relay_id,
        })
        .expect("valid result")
    };

    w.sealed(
        "join_relay_up_m1",
        "d2h",
        "proxy 2 relays m1 (single Wire frame); unsolicited, request 0",
        FrameKind::HostOps,
        0,
        up(object(
            header(jr::RelayDirection::Up, 1, jr::RelayState::Continue, -71),
            join_message(59, 1),
        )),
    );
    let down_m2 = jr::encode_join_relay_down(&jr::JoinRelayDown {
        to_proxy: PEER_NODE,
        object: object(
            header(jr::RelayDirection::Down, 2, jr::RelayState::Continue, 0),
            join_message(372, 2),
        ),
    })
    .expect("valid down");
    w.sealed(
        "join_relay_down_m2",
        "h2d",
        "the Site Authority answers with m2 toward proxy 2",
        FrameKind::HostOps,
        500,
        down_m2.clone(),
    );
    w.sealed(
        "join_relay_down_m2_grant",
        "d2h",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        topup(down_m2.len()),
    );
    w.sealed(
        "join_relay_result_m2",
        "d2h",
        "Ok: m2 handed to the Wire lane as 4 chunks (not yet delivered)",
        FrameKind::HostOps,
        500,
        result(ConfigOpsResult::Ok, RELAY_ID),
    );
    w.sealed(
        "join_relay_up_m3",
        "d2h",
        "m3 arrives from proxy 2 as 4 Wire chunks, reassembled by the gateway",
        FrameKind::HostOps,
        0,
        up(object(
            header(jr::RelayDirection::Up, 3, jr::RelayState::Continue, -64),
            join_message(404, 3),
        )),
    );
    let down_m4 = jr::encode_join_relay_down(&jr::JoinRelayDown {
        to_proxy: PEER_NODE,
        object: object(
            header(jr::RelayDirection::Down, 4, jr::RelayState::Final, 0),
            join_message(353, 4),
        ),
    })
    .expect("valid down");
    w.sealed(
        "join_relay_down_m4",
        "h2d",
        "final m4 (allow): the proxy frees its slot after delivery",
        FrameKind::HostOps,
        501,
        down_m4.clone(),
    );
    w.sealed(
        "join_relay_down_m4_grant",
        "d2h",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        topup(down_m4.len()),
    );
    w.sealed(
        "join_relay_result_m4",
        "d2h",
        "Ok: m4 handed to the Wire lane",
        FrameKind::HostOps,
        501,
        result(ConfigOpsResult::Ok, RELAY_ID),
    );
    let abort = jr::encode_join_relay_abort(&jr::JoinRelayAbort {
        proxy: PEER_NODE,
        relay_id: RELAY_ID,
        reason: jr::RelayAbortReason::HostAborted,
    })
    .expect("valid abort");
    w.sealed(
        "join_relay_abort_finished",
        "h2d",
        "the host cancels the relay it already finished",
        FrameKind::HostOps,
        502,
        abort.clone(),
    );
    w.sealed(
        "join_relay_abort_grant",
        "d2h",
        "rx grant advances past the host_ops request",
        FrameKind::Credit,
        0,
        topup(abort.len()),
    );
    w.sealed(
        "join_relay_result_abort",
        "d2h",
        "Invalid: the gateway no longer knows a finished relay",
        FrameKind::HostOps,
        502,
        result(ConfigOpsResult::Invalid, RELAY_ID),
    );
    w.sealed(
        "join_relay_proxy_abort",
        "d2h",
        "proxy 2 gave up a second relay (device silent): unsolicited 0x62",
        FrameKind::HostOps,
        0,
        jr::encode_join_relay_abort(&jr::JoinRelayAbort {
            proxy: PEER_NODE,
            relay_id: RELAY_ID + 1,
            reason: jr::RelayAbortReason::ProxyAborted,
        })
        .expect("valid abort"),
    );
    w.sealed(
        "close",
        "h2d",
        "host requests session close; device drains",
        FrameKind::Credit,
        503,
        vec![CREDIT_CLOSE],
    );
    finish_session(root, &frames_dir, "join-relay", CAPABILITY_JR, &proof, &w)
}
