//! Regenerates the shared Wire v1 golden vectors under `protocol/golden/`.
//! Run with: `cargo run -p routeloom-wire --example gen_golden`
//!
//! All vectors use the deterministic test cipher (`TestSecurity`, see
//! `src/test_security.rs` and `tests/cpp/test_security.hpp`) with a fresh
//! provider per operation, so every link/end crypto counter starts at 0.

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_wire::test_security::TestSecurity;
use routeloom_wire::*;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/golden")
}

struct Case {
    name: &'static str,
    comment: &'static str,
    frame: PlainFrame,
    forward: Option<(u64, u64, u32)>, // (local_node, next_hop, remaining_deadline_ms)
}

#[allow(clippy::too_many_arguments)]
fn plain(
    frame_type: FrameType,
    flags: u8,
    delivery: DeliveryClass,
    delivery_round: u8,
    hop_remaining: u8,
    origin: u64,
    destination: u64,
    previous_hop: u64,
    next_hop: u64,
    session: u32,
    sequence: u64,
    lifetime_ms: u32,
    payload: &[u8],
) -> PlainFrame {
    let mut frame = PlainFrame {
        header: Header {
            frame_type,
            flags,
            delivery,
            delivery_round,
            hop_remaining,
            network: 1,
            origin,
            destination,
            previous_hop,
            next_hop,
            message: MessageId { session, sequence },
            remaining_deadline_ms: lifetime_ms,
            original_lifetime_ms: lifetime_ms,
            link_epoch: 1,
            end_epoch: 1,
            ..Header::default()
        },
        ..PlainFrame::default()
    };
    frame.payload[..payload.len()].copy_from_slice(payload);
    frame.payload_size = payload.len();
    frame
}

fn encode(frame: &PlainFrame) -> Vec<u8> {
    let mut security = TestSecurity::new();
    let mut encoded = EncodedFrame::default();
    encode_new(frame, &mut security, &mut encoded).expect("golden encode failed");
    encoded.view().to_vec()
}

fn write_valid(dir: &Path, case: &Case) {
    let frame = &case.frame;
    let header = &frame.header;
    let encoded = encode(frame);
    let mut json = format!(
        "{{\n  \"format\": \"routeloom-wire-v1-golden\",\n  \"name\": \"{}\",\n  \"comment\": \"{}\",\n  \"type\": {},\n  \"flags\": {},\n  \"delivery\": {},\n  \"delivery_round\": {},\n  \"hop_remaining\": {},\n  \"network\": {},\n  \"origin\": {},\n  \"destination\": {},\n  \"previous_hop\": {},\n  \"next_hop\": {},\n  \"session\": {},\n  \"sequence\": {},\n  \"remaining_deadline_ms\": {},\n  \"original_lifetime_ms\": {},\n  \"link_epoch\": {},\n  \"end_epoch\": {},\n  \"payload_hex\": \"{}\",\n  \"encoded_hex\": \"{}\"",
        case.name,
        case.comment,
        header.frame_type as u8,
        header.flags,
        header.delivery as u8,
        header.delivery_round,
        header.hop_remaining,
        header.network,
        header.origin,
        header.destination,
        header.previous_hop,
        header.next_hop,
        header.message.session,
        header.message.sequence,
        header.remaining_deadline_ms,
        header.original_lifetime_ms,
        header.link_epoch,
        header.end_epoch,
        hex(&frame.payload[..frame.payload_size]),
        hex(&encoded),
    );
    if let Some((local, next, budget)) = case.forward {
        // The relay opens the link layer and re-wraps it for the next hop with
        // a fresh provider; the end-protected plaintext is carried unchanged.
        let mut opener = TestSecurity::new();
        let mut opened = LinkOpenedFrame::default();
        open_link(&encoded, local, &mut opener, &mut opened).expect("golden open_link failed");
        let mut forwarder = TestSecurity::new();
        let mut forwarded = EncodedFrame::default();
        forward(&opened, local, next, opened.header.link_epoch, budget, &mut forwarder, &mut forwarded)
            .expect("golden forward failed");
        json += &format!(
            ",\n  \"fwd_local_node\": {},\n  \"fwd_next_hop\": {},\n  \"fwd_remaining_deadline_ms\": {},\n  \"fwd_encoded_hex\": \"{}\"",
            local,
            next,
            budget,
            hex(forwarded.view()),
        );
    }
    json += "\n}\n";
    fs::write(dir.join(format!("{}.json", case.name)), json).expect("write valid vector");
}

fn write_invalid(
    dir: &Path,
    name: &str,
    comment: &str,
    expect: &str,
    local_node: u64,
    end_node: Option<u64>,
    encoded: &[u8],
) {
    let mut json = format!(
        "{{\n  \"format\": \"routeloom-wire-v1-golden\",\n  \"name\": \"{}\",\n  \"comment\": \"{}\",\n  \"expect\": \"{}\",\n  \"local_node\": {},",
        name, comment, expect, local_node,
    );
    if let Some(node) = end_node {
        json += &format!("\n  \"end_node\": {},", node);
    }
    json += &format!("\n  \"encoded_hex\": \"{}\"\n}}\n", hex(encoded));
    fs::write(dir.join(format!("{}.json", name)), json).expect("write invalid vector");
}

fn ack_payload(
    accepted_type: FrameType,
    origin: u64,
    session: u32,
    sequence: u64,
    round: u8,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(22);
    payload.push(accepted_type as u8);
    payload.extend_from_slice(&origin.to_be_bytes());
    payload.extend_from_slice(&session.to_be_bytes());
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.push(round);
    payload
}

fn receipt_payload(
    origin: u64,
    destination: u64,
    session: u32,
    sequence: u64,
    round: u8,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(30);
    payload.extend_from_slice(&origin.to_be_bytes());
    payload.extend_from_slice(&destination.to_be_bytes());
    payload.extend_from_slice(&session.to_be_bytes());
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.push(round);
    payload.push(0);
    payload
}

// Wire v1 route record: destination(8) + origin generation(2) +
// sequence(2) + metric(2) = 14 bytes.
fn route_update_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(29);
    payload.push(2_u8); // record count
    payload.extend_from_slice(&2_u64.to_be_bytes()); // self: destination 2
    payload.extend_from_slice(&1_u16.to_be_bytes()); // generation
    payload.extend_from_slice(&0_u16.to_be_bytes()); // sequence
    payload.extend_from_slice(&0_u16.to_be_bytes()); // metric
    payload.extend_from_slice(&3_u64.to_be_bytes()); // destination 3
    payload.extend_from_slice(&1_u16.to_be_bytes()); // generation
    payload.extend_from_slice(&101_u16.to_be_bytes());
    payload.extend_from_slice(&10_u16.to_be_bytes());
    payload
}

fn main() {
    let dir = golden_dir();
    let valid_dir = dir.join("valid");
    let invalid_dir = dir.join("invalid");
    fs::create_dir_all(&valid_dir).expect("create valid dir");
    fs::create_dir_all(&invalid_dir).expect("create invalid dir");

    let mut payload_128 = [0_u8; MAX_APPLICATION_PAYLOAD];
    for (i, byte) in payload_128.iter_mut().enumerate() {
        *byte = (i * 31 + 7) as u8;
    }

    let cases = [
        Case {
            name: "data_10b_end_protected",
            comment: "10-byte application payload, end-to-end protected, hop 1->2 of 1->2->3",
            frame: plain(
                FrameType::Data,
                FLAG_END_PROTECTED,
                DeliveryClass::Reliable,
                0,
                4,
                1,
                3,
                1,
                2,
                7,
                9,
                5000,
                b"route-loom",
            ),
            forward: None,
        },
        Case {
            name: "data_128b_end_protected",
            comment: "maximum 128-byte payload; total frame is 248 of 250 bytes",
            frame: plain(
                FrameType::Data,
                FLAG_END_PROTECTED,
                DeliveryClass::Reliable,
                0,
                10,
                1,
                2,
                1,
                2,
                7,
                10,
                30000,
                &payload_128,
            ),
            forward: None,
        },
        Case {
            name: "hop_accept_shortest",
            comment: "shortest HOP_ACCEPT emitted by the reference node (22-byte ack payload)",
            frame: plain(
                FrameType::HopAccept,
                0,
                DeliveryClass::BestEffort,
                0,
                1,
                2,
                1,
                2,
                1,
                7,
                9,
                1000,
                &ack_payload(FrameType::Data, 1, 7, 9, 0),
            ),
            forward: None,
        },
        Case {
            name: "end_receipt",
            comment: "END_RECEIPT for the data_10b message, end-to-end protected, 3->1",
            frame: plain(
                FrameType::EndReceipt,
                FLAG_END_PROTECTED,
                DeliveryClass::Reliable,
                0,
                4,
                3,
                1,
                3,
                1,
                7,
                9,
                5000,
                &receipt_payload(1, 3, 7, 9, 0),
            ),
            forward: None,
        },
        Case {
            name: "route_update",
            comment: "ROUTE_UPDATE with two route records, link protection only",
            frame: plain(
                FrameType::RouteUpdate,
                0,
                DeliveryClass::BestEffort,
                0,
                1,
                2,
                1,
                2,
                1,
                102,
                5,
                1000,
                &route_update_payload(),
            ),
            forward: None,
        },
        Case {
            name: "data_forwarded",
            comment:
                "data_10b_end_protected relayed at node 2: outer crypto re-wrapped, inner untouched",
            frame: plain(
                FrameType::Data,
                FLAG_END_PROTECTED,
                DeliveryClass::Reliable,
                0,
                4,
                1,
                3,
                1,
                2,
                7,
                9,
                5000,
                b"route-loom",
            ),
            forward: Some((2, 3, 4900)),
        },
        Case {
            name: "data_link_only",
            comment: "unprotected-payload DATA (link layer protection only)",
            frame: plain(
                FrameType::Data,
                0,
                DeliveryClass::BestEffort,
                0,
                1,
                1,
                2,
                1,
                2,
                7,
                11,
                2000,
                b"link-only",
            ),
            forward: None,
        },
    ];
    for case in &cases {
        write_valid(&valid_dir, case);
    }

    // Invalid vectors derived from the data_10b_end_protected encoding.
    let base = encode(&cases[0].frame);

    let mut truncated = base.clone();
    truncated.truncate(60);
    write_invalid(
        &invalid_dir,
        "truncated",
        "frame cut inside the link ciphertext",
        "link",
        2,
        None,
        &truncated,
    );

    let mut unknown_type = base.clone();
    unknown_type[4] = 0xee;
    write_invalid(
        &invalid_dir,
        "unknown_type",
        "frame type 0xEE is not assigned in v1",
        "link",
        2,
        None,
        &unknown_type,
    );

    let mut reserved_byte = base.clone();
    reserved_byte[9] = 0x01;
    write_invalid(
        &invalid_dir,
        "reserved_byte",
        "reserved header byte set to 0x01",
        "link",
        2,
        None,
        &reserved_byte,
    );

    let mut unknown_flag = base.clone();
    unknown_flag[5] |= 0x02;
    write_invalid(
        &invalid_dir,
        "unknown_flag",
        "undefined flag bit 0x02 set",
        "link",
        2,
        None,
        &unknown_flag,
    );

    let mut old_version = base.clone();
    old_version[2] = 0;
    old_version[3] = 1;
    write_invalid(
        &invalid_dir,
        "old_version",
        "provisional v0.1 frame must be rejected",
        "link",
        2,
        None,
        &old_version,
    );

    let mut future_version = base.clone();
    future_version[2] = 2;
    write_invalid(
        &invalid_dir,
        "future_version",
        "unsupported major version 2",
        "link",
        2,
        None,
        &future_version,
    );

    let mut length_mismatch = base.clone();
    let declared = u16::from_be_bytes([length_mismatch[10], length_mismatch[11]]);
    length_mismatch[10..12].copy_from_slice(&(declared + 1).to_be_bytes());
    write_invalid(
        &invalid_dir,
        "length_mismatch",
        "payload_length exceeds actual body",
        "link",
        2,
        None,
        &length_mismatch,
    );

    let mut trailing_garbage = base.clone();
    trailing_garbage.push(0xaa);
    write_invalid(
        &invalid_dir,
        "trailing_garbage",
        "one extra byte after the link tag",
        "link",
        2,
        None,
        &trailing_garbage,
    );

    let mut tampered_tag = base.clone();
    let last = tampered_tag.len() - 1;
    tampered_tag[last] ^= 0x01;
    write_invalid(
        &invalid_dir,
        "tampered_tag",
        "single bit flipped in the link AEAD tag",
        "link",
        2,
        None,
        &tampered_tag,
    );

    let mut tampered_aad = base.clone();
    tampered_aad[15] = 0x03; // network 1 -> 3, still header-valid but tag-invalid
    write_invalid(
        &invalid_dir,
        "tampered_aad",
        "AAD-covered header field (network) altered",
        "link",
        2,
        None,
        &tampered_aad,
    );

    // End-tag tamper: relay at node 2 corrupts the end tag inside the protected
    // payload and re-wraps the link layer, so the link open succeeds and only
    // the end-to-end open must fail.
    let mut opener = TestSecurity::new();
    let mut opened = LinkOpenedFrame::default();
    open_link(&base, 2, &mut opener, &mut opened).expect("base open failed");
    let inner = opened.protected_payload_size - 1;
    opened.protected_payload[inner] ^= 0x01;
    let mut forwarder = TestSecurity::new();
    let mut forwarded = EncodedFrame::default();
    forward(&opened, 2, 3, opened.header.link_epoch, 4900, &mut forwarder, &mut forwarded).expect("forward failed");
    write_invalid(
        &invalid_dir,
        "tampered_end_tag",
        "end-to-end tag corrupted before the last link re-wrap",
        "end",
        3,
        Some(3),
        forwarded.view(),
    );

    println!(
        "wrote {} valid + 11 invalid vectors to {}",
        cases.len(),
        dir.display()
    );
}
