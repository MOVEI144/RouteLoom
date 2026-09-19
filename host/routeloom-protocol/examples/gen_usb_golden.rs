//! Regenerates protocol/usb-golden/*.json — shared session vectors for the
//! USB device bridge. The C++ harness (tests/cpp/test_usb.cpp) replays the
//! host wire bytes into a real UsbBridge and requires byte-identical device
//! output; the Rust harness (tests/usb_golden.rs) verifies the same files.
//! Run: cargo run -p routeloom-protocol --example gen_usb_golden

use routeloom_protocol::dev_session::*;
use routeloom_protocol::{encode_frame, Frame, FrameKind};
use std::fs;
use std::path::{Path, PathBuf};

const SECRET: &[u8] = b"routeloom-dev-secret";
const HOST_NONCE: u64 = 0x0102_0304_0506_0708;
const DEVICE_NONCE: u64 = 0xa0b0_c0d0_e0f0_0102;
const NODE: u64 = 1;
const BOOT: u64 = 0x0000_00b0_071d_0001;
const NETWORK: u64 = 7;
const CAPABILITY: u32 = 3;
const PRINCIPAL: &[u8] = b"host-operator";
const MESH_SESSION: u32 = 7001; // gateway message_session
const PEER_SESSION: u32 = 2002; // node-2 message_session
const PEER_NODE: u64 = 2;
const RX_GRANT_FRAMES: u64 = 8; // device headroom (C++ kRxGrantFrames)
const RX_GRANT_BYTES: u64 = 16384; // device headroom (C++ kRxGrantBytes)
const TX_GRANT_FRAMES: u64 = 16; // host grant to device
const TX_GRANT_BYTES: u64 = 65536;

fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
    let proof = derive_session_proof(SECRET, &transcript.encode());
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

    // 7: host command into the mesh. inner = destination || payload.
    let payload = b"mesh-down";
    let mut data_inner = Vec::new();
    data_inner.extend_from_slice(&PEER_NODE.to_be_bytes());
    data_inner.extend_from_slice(payload);
    steps.push(h2d(
        "data_to_mesh",
        "host command: send 9-byte payload to node 2",
        FrameKind::DataToMesh,
        0,
        103,
        data_inner,
    ));

    // 8: device advances the cumulative rx grant after releasing the buffer.
    // Consumed = 1 frame, decoded_len = 30 + protected_body_len. The
    // protected body was counter||tag||inner = 24 + (8 + payload).
    let consumed_bytes = (30 + 24 + 8 + payload.len()) as u64;
    let mut topup_inner = vec![CREDIT_GRANT];
    topup_inner.extend_from_slice(&(1 + RX_GRANT_FRAMES).to_be_bytes());
    topup_inner.extend_from_slice(&(consumed_bytes + RX_GRANT_BYTES).to_be_bytes());
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
    Ok(())
}
