//! Shared-vector interop check for the USB device bridge. Loads the same
//! protocol/usb-golden files as tests/cpp/test_usb.cpp: host wire bytes are
//! re-encoded here and must match the golden bytes; device wire bytes are
//! decoded and their session tags/counters verified against the dev-session
//! construction both languages implement.

use routeloom_protocol::dev_session::*;
use routeloom_protocol::host_ops::*;
use routeloom_protocol::{encode_frame, Frame, StreamDecoder, MAX_DECODED_FRAME};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("protocol/usb-golden")
}

fn parse_flat_json(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let key_begin = match text[pos..].find('"') {
            Some(offset) => pos + offset,
            None => break,
        };
        let key_end = text[key_begin + 1..]
            .find('"')
            .map(|offset| key_begin + 1 + offset)
            .expect("unterminated key");
        let colon = text[key_end + 1..]
            .find(':')
            .map(|offset| key_end + 1 + offset)
            .expect("missing colon");
        let mut cursor = colon + 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let (value, next);
        if cursor < bytes.len() && bytes[cursor] == b'"' {
            let value_end = text[cursor + 1..]
                .find('"')
                .map(|offset| cursor + 1 + offset)
                .expect("unterminated value");
            value = text[cursor + 1..value_end].to_string();
            next = value_end + 1;
        } else {
            let mut value_end = cursor;
            while value_end < bytes.len()
                && (bytes[value_end].is_ascii_digit() || bytes[value_end] == b'-')
            {
                value_end += 1;
            }
            value = text[cursor..value_end].to_string();
            next = value_end;
        }
        fields.insert(text[key_begin + 1..key_end].to_string(), value);
        pos = next;
    }
    fields
}

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    fields.get(key).map(String::as_str).unwrap_or("")
}

fn u64_field(fields: &BTreeMap<String, String>, key: &str) -> u64 {
    field(fields, key).parse().expect("u64 field")
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).expect("hex utf8");
            u8::from_str_radix(s, 16).expect("hex digit")
        })
        .collect()
}

fn load(path: &Path) -> BTreeMap<String, String> {
    parse_flat_json(&fs::read_to_string(path).expect("readable vector"))
}

fn decode_wire(wire: &[u8]) -> Frame {
    let mut decoder = StreamDecoder::default();
    let mut frames = Vec::new();
    for chunk in wire.chunks(3) {
        // Chunked streaming must not change the result.
        frames.extend(decoder.push(chunk));
    }
    assert_eq!(frames.len(), 1, "expected exactly one frame per vector");
    frames.pop().expect("one frame").expect("decodable vector")
}

#[test]
fn usb_session_vectors_are_byte_exact() {
    let root = golden_dir();
    let session = load(&root.join("session.json"));
    let secret = unhex(field(&session, "secret_hex"));
    let transcript = Transcript {
        host_nonce: u64_field(&session, "host_nonce"),
        device_nonce: u64_field(&session, "device_nonce"),
        version: u64_field(&session, "version") as u8,
        node: u64_field(&session, "node"),
        boot: u64_field(&session, "boot"),
        network: u64_field(&session, "network"),
        capability: u64_field(&session, "capability") as u32,
        principal: field(&session, "principal").as_bytes().to_vec(),
    };
    assert_eq!(transcript.encode().unwrap().len(), TRANSCRIPT_SIZE);
    let proof = derive_session_proof(&secret, &transcript.encode().unwrap());
    assert_eq!(proof.session_id, u64_field(&session, "session_id"));
    assert_eq!(
        proof.hello_tag.to_vec(),
        unhex(field(&session, "hello_tag_hex"))
    );
    assert_eq!(
        proof.auth_tag.to_vec(),
        unhex(field(&session, "auth_tag_hex"))
    );
    assert_eq!(
        proof.auth_ok_tag.to_vec(),
        unhex(field(&session, "auth_ok_tag_hex"))
    );
    assert_eq!(
        proof.key.to_vec(),
        unhex(field(&session, "session_key_hex"))
    );

    let mut frame_files: Vec<PathBuf> = fs::read_dir(root.join("frames"))
        .expect("frames dir")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    frame_files.sort();
    assert!(
        frame_files.len() >= 10,
        "session scenario should be complete"
    );

    let mut d2h_counter = 0_u64;
    let mut h2d_counter = 0_u64;
    let mut saw_auth_ok = false;
    for path in &frame_files {
        let vector = load(path);
        let name = field(&vector, "name").to_string();
        let direction = field(&vector, "direction");
        let wire = unhex(field(&vector, "wire_hex"));
        assert!(wire.len() <= MAX_DECODED_FRAME + 64);
        let frame = decode_wire(&wire);
        assert_eq!(frame.kind as u8, u64_field(&vector, "kind") as u8, "{name}");
        assert_eq!(frame.flags, u64_field(&vector, "flags") as u16, "{name}");
        assert_eq!(frame.session, u64_field(&vector, "session"), "{name}");
        assert_eq!(frame.request, u64_field(&vector, "request"), "{name}");
        assert_eq!(frame.body, unhex(field(&vector, "body_hex")), "{name}");

        if direction == "h2d" {
            // The Rust encoder must reproduce the exact golden wire bytes.
            let reparsed = Frame {
                kind: frame.kind,
                flags: frame.flags,
                session: frame.session,
                request: frame.request,
                body: frame.body.clone(),
            };
            assert_eq!(encode_frame(&reparsed).expect("re-encode"), wire, "{name}");
        }

        match name.as_str() {
            "hello" => {
                assert_eq!(frame.session, 0);
                assert_eq!(frame.body, {
                    let mut body = transcript.host_nonce.to_be_bytes().to_vec();
                    body.extend_from_slice(&[1, 1, transcript.principal.len() as u8]);
                    body.extend_from_slice(&transcript.principal);
                    body
                });
            }
            "hello_ack" => {
                assert_eq!(frame.body.len(), 8 + 1 + 8 + 8 + 8 + 4 + DEV_TAG_SIZE);
                assert_eq!(&frame.body[..8], &transcript.device_nonce.to_be_bytes());
                assert_eq!(frame.body[8], 1);
                assert_eq!(&frame.body[37..], &proof.hello_tag);
            }
            "auth" => {
                assert_eq!(frame.flags & FLAG_AUTH, FLAG_AUTH);
                assert_eq!(frame.body, proof.auth_tag.to_vec());
            }
            "auth_ok" => {
                saw_auth_ok = true;
                assert_eq!(&frame.body[..DEV_TAG_SIZE], &proof.auth_ok_tag);
                assert_eq!(&frame.body[DEV_TAG_SIZE..], &proof.session_id.to_be_bytes());
            }
            _ => {
                // Every post-auth frame carries session id + direction
                // counter + tag verified on receipt.
                assert_eq!(frame.session, proof.session_id, "{name}");
                let direction = if direction == "h2d" {
                    DIRECTION_HOST_TO_DEVICE
                } else {
                    DIRECTION_DEVICE_TO_HOST
                };
                let (counter, inner) = open_body(&proof.key, direction, &frame).expect("valid tag");
                let expected = if direction == DIRECTION_HOST_TO_DEVICE {
                    &mut h2d_counter
                } else {
                    &mut d2h_counter
                };
                assert_eq!(counter, *expected, "{name} counter must be sequential");
                *expected += 1;
                assert_eq!(inner, unhex(field(&vector, "inner_hex")), "{name}");
                // Host-ops inners must parse under the shared codec with the
                // scenario's expected outcomes.
                match name.as_str() {
                    "submit_seq3" => {
                        let request = decode_submit(inner).expect("submit parses");
                        assert_eq!(request.dispatch_seq, 3);
                        assert_eq!(request.canonical.len(), 35);
                    }
                    "submit_seq3_receipt" => {
                        let receipt = decode_receipt(inner, SUB_SUBMIT).expect("receipt parses");
                        assert_eq!(receipt.result, HostOpsResult::Ok);
                        assert_eq!(receipt.state, SlotState::Sent);
                        assert_eq!((receipt.msg_session, receipt.msg_seq), (7001, 2));
                        assert!(receipt.msg_valid);
                        assert_eq!(receipt.evidence, Evidence::GatewayAccepted);
                    }
                    "query_seq3_resp" => {
                        let response = decode_query_response(inner).expect("query response parses");
                        assert_eq!(response.result, HostOpsResult::Ok);
                        assert_eq!(response.state, SlotState::Sent);
                        assert_eq!(response.operation_id[23], 1);
                    }
                    "retire_prefix_resp" => {
                        let response =
                            decode_retire_response(inner).expect("retire response parses");
                        assert_eq!(response.result, HostOpsResult::Ok);
                        assert_eq!(response.retired_through, 2);
                    }
                    "time_sample_resp" => {
                        let response =
                            decode_time_sample_response(inner).expect("time sample parses");
                        assert_eq!(response.result, HostOpsResult::Ok);
                        assert_eq!(response.nonce, 0x5A5A);
                    }
                    _ => {}
                }
            }
        }
    }
    assert!(saw_auth_ok);
    // The scenario exercises both directions of the protected channel:
    // tx_grant, data_to_mesh, 7 host_ops requests, keepalive, close.
    assert!(d2h_counter >= 5);
    assert_eq!(h2d_counter, 11);
}

#[test]
fn tampered_session_frames_are_rejected() {
    let root = golden_dir();
    let session = load(&root.join("session.json"));
    let secret = unhex(field(&session, "secret_hex"));
    let transcript = Transcript {
        host_nonce: u64_field(&session, "host_nonce"),
        device_nonce: u64_field(&session, "device_nonce"),
        version: 1,
        node: u64_field(&session, "node"),
        boot: u64_field(&session, "boot"),
        network: u64_field(&session, "network"),
        capability: u64_field(&session, "capability") as u32,
        principal: field(&session, "principal").as_bytes().to_vec(),
    };
    let proof = derive_session_proof(&secret, &transcript.encode().unwrap());
    // Found by step name, not file number, so scenario insertions cannot
    // silently point this tamper check at the wrong frame.
    let mut keepalive_path: Option<PathBuf> = None;
    for entry in fs::read_dir(root.join("frames")).expect("frames dir") {
        let path = entry.expect("dir entry").path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("_keepalive.json"))
        {
            keepalive_path = Some(path);
        }
    }
    let keepalive = load(&keepalive_path.expect("keepalive vector"));
    let frame = decode_wire(&unhex(field(&keepalive, "wire_hex")));

    // A flipped tag bit must fail verification.
    let mut forged = frame.clone();
    forged.body[10] ^= 1;
    assert!(open_body(&proof.key, DIRECTION_HOST_TO_DEVICE, &forged).is_err());
    // A wrong-direction tag must fail as well.
    assert!(open_body(&proof.key, DIRECTION_DEVICE_TO_HOST, &frame).is_err());
    // Re-encoding the decoded frame stays byte-identical.
    assert_eq!(
        encode_frame(&frame).expect("re-encode"),
        unhex(field(&keepalive, "wire_hex"))
    );
}

/// protocol/usb-golden/node-status: the node_status_v1 scenario. Host
/// frames must re-encode byte-exactly, every device frame must open under
/// the session key with sequential counters, and the 0x40-0x42 inners must
/// decode under the Rust codec with the scenario's expected contents.
#[test]
fn node_status_vectors_are_byte_exact() {
    use routeloom_protocol::node_status::*;

    let root = golden_dir().join("node-status");
    let session = load(&root.join("session.json"));
    let capability = u64_field(&session, "capability") as u32;
    assert_eq!(capability, 0x3 | CAP_HOST_OPS_V1 | CAP_NODE_STATUS_V1);
    let transcript = Transcript {
        host_nonce: u64_field(&session, "host_nonce"),
        device_nonce: u64_field(&session, "device_nonce"),
        version: 1,
        node: u64_field(&session, "node"),
        boot: u64_field(&session, "boot"),
        network: u64_field(&session, "network"),
        capability,
        principal: field(&session, "principal").as_bytes().to_vec(),
    };
    let proof = derive_session_proof(
        &unhex(field(&session, "secret_hex")),
        &transcript.encode().unwrap(),
    );
    assert_eq!(proof.session_id, u64_field(&session, "session_id"));
    assert_eq!(
        proof.key.to_vec(),
        unhex(field(&session, "session_key_hex"))
    );

    let mut files: Vec<PathBuf> = fs::read_dir(root.join("frames"))
        .expect("frames dir")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    let (mut d2h, mut h2d) = (0_u64, 0_u64);
    let mut pages = Vec::new();
    let mut events = Vec::new();
    for path in &files {
        let vector = load(path);
        let name = field(&vector, "name").to_string();
        let direction = field(&vector, "direction");
        let wire = unhex(field(&vector, "wire_hex"));
        let frame = decode_wire(&wire);
        if direction == "h2d" {
            assert_eq!(encode_frame(&frame).expect("re-encode"), wire, "{name}");
        }
        if frame.session == 0 {
            continue; // handshake frames
        }
        let dir = if direction == "h2d" {
            DIRECTION_HOST_TO_DEVICE
        } else {
            DIRECTION_DEVICE_TO_HOST
        };
        let (counter, inner) = open_body(&proof.key, dir, &frame).expect("valid tag");
        let expected = if dir == DIRECTION_HOST_TO_DEVICE {
            &mut h2d
        } else {
            &mut d2h
        };
        assert_eq!(counter, *expected, "{name}");
        *expected += 1;
        assert_eq!(inner, unhex(field(&vector, "inner_hex")), "{name}");
        match node_status_sub(inner) {
            Some(SUB_NODE_STATUS_QUERY) => {
                let query = decode_node_status_query(inner).expect("query parses");
                assert_eq!((query.after, query.max_entries), (0, PAGE_MAX as u8));
            }
            Some(SUB_NODE_STATUS_PAGE) => pages.push(decode_node_status_page(inner).unwrap()),
            Some(SUB_NODE_EVENT) => {
                assert_eq!(frame.request, 0, "events are unsolicited");
                events.push(decode_node_event(inner).unwrap());
            }
            _ => {}
        }
    }
    assert_eq!(pages.len(), 2);
    assert!(pages.iter().all(|p| p.ok() && p.armed() && !p.more()));
    let first = pages[0].entries[0];
    assert!(first.neighbor_active() && first.reachable() && first.direct());
    assert_eq!((first.node, first.link_cost, first.route_metric), (2, 1, 1));
    assert!(!first.heard_valid() && !first.rssi_valid());
    assert_eq!(pages[1].event_seq, 2);
    assert!(!pages[1].entries[0].reachable() && pages[1].entries[0].neighbor());
    let kinds: Vec<_> = events.iter().map(|e| (e.sequence, e.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            (1, NodeEventKind::NeighborDown),
            (2, NodeEventKind::RouteDown)
        ]
    );
    assert_eq!(h2d, 4); // tx_grant, subscribe, resync, close
}
