//! Shared golden-vector harness for the autonomy payload codecs and the RLD1
//! carrier: loads the same protocol/autonomy-golden/*.json files as the C++
//! harness (tests/cpp/test_autonomy.cpp) and asserts byte-for-byte encode and
//! decode equivalence. Also pins the coarse membership allowlist matrix
//! against protocol/semantics.json expectations.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_wire::admission::{
    bootstrap_frame_type, frame_allowed, rld1_kind_allowed, AdmissionCarrier, MembershipState,
};
use routeloom_wire::autonomy::*;
use routeloom_wire::FrameType;

type Fields = BTreeMap<String, String>;

/// Minimal extractor for the flat "key": value objects used by the golden
/// files. Same subset as the Wire v1 harness: strings or unsigned integers.
fn parse_flat_json(text: &str) -> Fields {
    let bytes = text.as_bytes();
    let mut fields = Fields::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(key_begin) = find(bytes, b'"', pos) else {
            break;
        };
        let Some(key_end) = find(bytes, b'"', key_begin + 1) else {
            break;
        };
        let Some(colon) = find(bytes, b':', key_end + 1) else {
            break;
        };
        let mut cursor = colon + 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let value;
        if cursor < bytes.len() && bytes[cursor] == b'"' {
            let Some(value_end) = find(bytes, b'"', cursor + 1) else {
                break;
            };
            value = text[cursor + 1..value_end].to_string();
            pos = value_end + 1;
        } else {
            let mut value_end = cursor;
            while value_end < bytes.len()
                && (bytes[value_end].is_ascii_digit() || bytes[value_end] == b'-')
            {
                value_end += 1;
            }
            value = text[cursor..value_end].to_string();
            pos = value_end;
        }
        fields.insert(text[key_begin + 1..key_end].to_string(), value);
    }
    fields
}

fn find(bytes: &[u8], byte: u8, from: usize) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|&b| b == byte)
        .map(|i| from + i)
}

fn u64_field(fields: &Fields, key: &str) -> u64 {
    fields
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .parse()
        .unwrap_or_else(|_| panic!("bad integer in field {key}"))
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "odd hex length");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn hex_field(fields: &Fields, key: &str) -> Vec<u8> {
    hex_decode(fields.get(key).unwrap_or_else(|| panic!("missing {key}")))
}

fn hash_field(fields: &Fields, key: &str) -> [u8; 32] {
    let raw = hex_field(fields, key);
    raw.try_into().expect("32-byte hash field")
}

fn nonce_field(fields: &Fields, key: &str) -> [u8; 16] {
    let raw = hex_field(fields, key);
    raw.try_into().expect("16-byte nonce field")
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/autonomy-golden")
}

fn list_json(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .expect("golden dir missing")
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            (path.extension().and_then(|e| e.to_str()) == Some("json")).then_some(path)
        })
        .collect();
    files.sort();
    files
}

fn encode_vector(codec: &str, fields: &Fields) -> Vec<u8> {
    let mut out = EncodedPayload::default();
    match codec {
        "busy" => {
            let payload = BusyPayload {
                subtype: match u64_field(fields, "subtype") {
                    1 => BusySubtype::Reject,
                    2 => BusySubtype::PressureHint,
                    other => panic!("bad busy subtype {other}"),
                },
                reason: match u64_field(fields, "reason") {
                    0 => BusyReason::None,
                    1 => BusyReason::QueueFull,
                    2 => BusyReason::PeerCapacityBusy,
                    3 => BusyReason::BudgetExhausted,
                    4 => BusyReason::PlannedAbsence,
                    5 => BusyReason::RateLimited,
                    other => panic!("bad busy reason {other}"),
                },
                referenced_type: FrameType::try_from(u64_field(fields, "referenced_type") as u8)
                    .expect("referenced type"),
                referenced_origin: u64_field(fields, "referenced_origin"),
                referenced_session: u64_field(fields, "referenced_session") as u32,
                referenced_sequence: u64_field(fields, "referenced_sequence"),
                referenced_round: u64_field(fields, "referenced_round") as u8,
                binding_generation: u64_field(fields, "binding_generation") as u32,
                feedback_sequence: u64_field(fields, "feedback_sequence") as u32,
                retry_after_ms: u64_field(fields, "retry_after_ms") as u32,
                pressure: u64_field(fields, "pressure") as u8,
            };
            busy_encode(&payload, &mut out).expect("busy encode");
            out.view().to_vec()
        }
        "time_sync" => {
            let payload = TimeSyncPayload {
                subtype: TimeSyncSubtype::Sample,
                source: u64_field(fields, "source"),
                sequence: u64_field(fields, "sequence") as u32,
                reference_ms: u64_field(fields, "reference_ms"),
                uncertainty_ms: u64_field(fields, "uncertainty_ms") as u32,
            };
            time_sync_encode(&payload, &mut out).expect("time_sync encode");
            out.view().to_vec()
        }
        "channel_notice" => {
            let payload = ChannelNoticePayload {
                subtype: ChannelNoticeSubtype::PlannedAbsence,
                subject: u64_field(fields, "subject"),
                channel_epoch: u64_field(fields, "channel_epoch") as u32,
                starts_in_ms: u64_field(fields, "starts_in_ms") as u32,
                duration_ms: u64_field(fields, "duration_ms") as u32,
                reason: match u64_field(fields, "reason") {
                    0 => AbsenceReason::None,
                    1 => AbsenceReason::SurveyVisit,
                    2 => AbsenceReason::HelperVisit,
                    3 => AbsenceReason::Cutover,
                    other => panic!("bad absence reason {other}"),
                },
                protected_cut_id: u64_field(fields, "protected_cut_id") as u16,
            };
            channel_notice_encode(&payload, &mut out).expect("channel_notice encode");
            out.view().to_vec()
        }
        "neighbor_probe" => {
            let payload = NeighborProbePayload {
                subtype: NeighborProbeSubtype::AvailabilityProbe,
                binding_generation: u64_field(fields, "binding_generation") as u32,
                probe_sequence: u64_field(fields, "probe_sequence") as u32,
                sent_ms: u64_field(fields, "sent_ms"),
                requested_lease_ms: u64_field(fields, "requested_lease_ms") as u32,
            };
            neighbor_probe_encode(&payload, &mut out).expect("neighbor_probe encode");
            out.view().to_vec()
        }
        "neighbor_result" => {
            let payload = NeighborResultPayload {
                subtype: NeighborResultSubtype::AvailabilityResult,
                binding_generation: u64_field(fields, "binding_generation") as u32,
                probe_sequence: u64_field(fields, "probe_sequence") as u32,
                result: match u64_field(fields, "result") {
                    0 => NeighborResultCode::Unknown,
                    1 => NeighborResultCode::Reachable,
                    2 => NeighborResultCode::NotListening,
                    3 => NeighborResultCode::Leaving,
                    other => panic!("bad result code {other}"),
                },
                pressure: u64_field(fields, "pressure") as u8,
                queue_delay_ms: u64_field(fields, "queue_delay_ms") as u32,
                est_airtime_us: u64_field(fields, "est_airtime_us") as u32,
                lease_granted_ms: u64_field(fields, "lease_granted_ms") as u32,
            };
            neighbor_result_encode(&payload, &mut out).expect("neighbor_result encode");
            out.view().to_vec()
        }
        "control_object" => {
            let payload = ControlObjectPayload {
                subtype: ControlObjectSubtype::Manifest,
                kind: match u64_field(fields, "kind") {
                    1 => ControlObjectKind::ChannelPlan,
                    2 => ControlObjectKind::RecoverySnapshot,
                    3 => ControlObjectKind::ConfigPermit,
                    4 => ControlObjectKind::ConfigRecovery,
                    5 => ControlObjectKind::TrustManifest,
                    other => panic!("bad object kind {other}"),
                },
                total_len: u64_field(fields, "total_len") as u16,
                object_hash: hash_field(fields, "object_hash_hex"),
            };
            control_object_encode(&payload, &mut out).expect("control_object encode");
            out.view().to_vec()
        }
        "object_chunk" => {
            let payload = ObjectChunkPayload {
                subtype: ObjectChunkSubtype::Chunk,
                object_hash: hash_field(fields, "object_hash_hex"),
                offset: u64_field(fields, "offset") as u16,
                data: hex_field(fields, "data_hex"),
            };
            object_chunk_encode(&payload, &mut out).expect("object_chunk encode");
            out.view().to_vec()
        }
        "object_ack" => {
            let payload = ObjectAckPayload {
                subtype: ObjectAckSubtype::Ack,
                object_hash: hash_field(fields, "object_hash_hex"),
                received_len: u64_field(fields, "received_len") as u16,
                status: match u64_field(fields, "status") {
                    0 => ObjectAckStatus::Ok,
                    1 => ObjectAckStatus::Incomplete,
                    2 => ObjectAckStatus::Failed,
                    other => panic!("bad ack status {other}"),
                },
            };
            object_ack_encode(&payload, &mut out).expect("object_ack encode");
            out.view().to_vec()
        }
        "bootstrap_auth" => {
            let payload = BootstrapAuthBody {
                phase: match u64_field(fields, "phase") {
                    1 => AuthPhase::Prove,
                    2 => AuthPhase::Confirm,
                    3 => AuthPhase::Finish,
                    other => panic!("bad auth phase {other}"),
                },
                step_index: u64_field(fields, "step_index") as u8,
                body: hex_field(fields, "body_hex"),
            };
            bootstrap_auth_encode(&payload, &mut out).expect("bootstrap_auth encode");
            out.view().to_vec()
        }
        "rld1" => {
            let envelope = Rld1Envelope {
                kind: FrameType::try_from(u64_field(fields, "kind") as u8).expect("kind"),
                flags: u64_field(fields, "flags") as u16,
                network_hint: u64_field(fields, "network_hint") as u32,
                claimed_node: u64_field(fields, "claimed_node"),
                transaction_nonce: nonce_field(fields, "nonce_hex"),
                capability_bits: u64_field(fields, "capability_bits") as u32,
                body: hex_field(fields, "body_hex"),
            };
            let mut bytes = Vec::new();
            rld1_encode(&envelope, &mut bytes).expect("rld1 encode");
            bytes
        }
        other => panic!("unknown codec {other}"),
    }
}

fn decode_vector(codec: &str, encoded: &[u8]) -> Result<(), String> {
    match codec {
        "busy" => busy_decode(encoded).map(|_| ()).map_err(|e| e.to_string()),
        "time_sync" => time_sync_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "channel_notice" => channel_notice_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "neighbor_probe" => neighbor_probe_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "neighbor_result" => neighbor_result_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "control_object" => control_object_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "object_chunk" => object_chunk_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "object_ack" => object_ack_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "bootstrap_auth" => bootstrap_auth_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "rld1" => rld1_decode(encoded).map(|_| ()).map_err(|e| e.to_string()),
        other => panic!("unknown codec {other}"),
    }
}

#[test]
fn valid_vectors_encode_and_decode_byte_exact() {
    let dir = golden_dir().join("valid");
    let files = list_json(&dir);
    assert!(files.len() >= 10, "expected at least 10 valid vectors");
    for path in files {
        let text = fs::read_to_string(&path).expect("read vector");
        let fields = parse_flat_json(&text);
        let name = fields.get("name").cloned().unwrap_or_default();
        let codec = fields.get("codec").expect("codec").as_str();
        let expected = hex_field(&fields, "encoded_hex");

        let produced = encode_vector(codec, &fields);
        assert_eq!(produced, expected, "{name}: encode bytes differ");
        decode_vector(codec, &expected).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
    }
}

#[test]
fn invalid_vectors_are_rejected() {
    let dir = golden_dir().join("invalid");
    let files = list_json(&dir);
    assert!(files.len() >= 10, "expected at least 10 invalid vectors");
    for path in files {
        let text = fs::read_to_string(&path).expect("read vector");
        let fields = parse_flat_json(&text);
        let name = fields.get("name").cloned().unwrap_or_default();
        let codec = fields.get("codec").expect("codec").as_str();
        let encoded = hex_field(&fields, "encoded_hex");

        if codec == "rld1" && fields.get("probe").is_some_and(|p| p == "false") {
            assert!(!rld1_probe(&encoded), "{name}: must not probe as RLD1");
        }
        assert!(
            decode_vector(codec, &encoded).is_err(),
            "{name}: unexpectedly decoded"
        );
    }
}

/// The coarse allowlist matrix must match protocol/semantics.json
/// `membership_allowlist` exactly: 6 states x all 28 known frame types.
#[test]
fn frame_allowed_matches_semantic_allowlist() {
    use FrameType::*;
    let all_types = [
        Discover,
        Offer,
        BootstrapAuth,
        MembershipResult,
        BootstrapChunk,
        BootstrapReply,
        MembershipQuery,
        Data,
        GroupData,
        GroupReport,
        HopAccept,
        EndReceipt,
        AppResult,
        Busy,
        Service,
        Control,
        TimeSync,
        ChannelNotice,
        RouteUpdate,
        RouteWithdraw,
        SeqnoRequest,
        RouteRequest,
        NeighborProbe,
        NeighborResult,
        Diagnostic,
        ControlObject,
        ObjectChunk,
        ObjectAck,
    ];
    assert_eq!(all_types.len(), 28);

    let expected = |state: MembershipState, t: FrameType| -> bool {
        match state {
            MembershipState::Unprovisioned | MembershipState::Discovering => {
                matches!(t, Discover | Offer)
            }
            MembershipState::Authenticating => matches!(
                t,
                Discover | Offer | BootstrapAuth | BootstrapChunk | BootstrapReply
            ),
            MembershipState::AuthorizedPendingCommit => matches!(
                t,
                MembershipQuery | MembershipResult | BootstrapChunk | BootstrapReply
            ),
            MembershipState::Member => true,
            MembershipState::Revoked => false,
        }
    };

    for state in [
        MembershipState::Unprovisioned,
        MembershipState::Discovering,
        MembershipState::Authenticating,
        MembershipState::AuthorizedPendingCommit,
        MembershipState::Member,
        MembershipState::Revoked,
    ] {
        for t in all_types {
            assert_eq!(
                frame_allowed(state, t),
                expected(state, t),
                "matrix mismatch {state:?} {t:?}"
            );
        }
        // Out-of-range membership values must default-deny in C++; here the
        // enum is total, so deny is enforced at TryFrom.
        assert!(MembershipState::try_from(6).is_err());
        assert!(MembershipState::try_from(255).is_err());
    }
    // Unknown type ids are unconstructable — TryFrom is the deny boundary.
    for bad in [0_u8, 8, 15, 27, 31, 52, 0xEE, 0xFF] {
        assert!(
            FrameType::try_from(bad).is_err(),
            "type {bad} must be unknown"
        );
    }
}

#[test]
fn rld1_kind_set_is_exactly_bootstrap() {
    for id in 1_u8..=7 {
        let kind = FrameType::try_from(id).expect("bootstrap id");
        assert_eq!(
            rld1_kind_allowed(kind),
            matches!(id, 1 | 2 | 3 | 5 | 6),
            "kind {id}"
        );
        assert!(bootstrap_frame_type(kind));
    }
    assert!(!rld1_kind_allowed(FrameType::Data));
    let _ = AdmissionCarrier::WireV1; // carrier type is part of the contract
}
