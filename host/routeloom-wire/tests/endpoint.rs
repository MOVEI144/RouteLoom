//! Shared golden-vector harness for the scope-gateway-config codec contract:
//! loads the same protocol/endpoint-golden/*.json files as the C++ harness
//! (tests/cpp/test_endpoint.cpp) and asserts byte-for-byte encode and decode
//! equivalence.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_wire::autonomy::EncodedPayload;
use routeloom_wire::endpoint::*;

type Fields = BTreeMap<String, String>;

/// Same flat "key": value subset as the other golden harnesses.
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

fn arr16(fields: &Fields, key: &str) -> [u8; 16] {
    hex_field(fields, key).try_into().expect("16-byte field")
}

fn arr32(fields: &Fields, key: &str) -> [u8; 32] {
    hex_field(fields, key).try_into().expect("32-byte field")
}

fn mac(fields: &Fields, key: &str) -> [u8; 6] {
    hex_field(fields, key).try_into().expect("6-byte MAC field")
}

fn scope_class(value: u64) -> ScopeClass {
    match value {
        1 => ScopeClass::Member,
        2 => ScopeClass::Commissioning,
        other => panic!("bad scope class {other}"),
    }
}

fn scope(value: u64) -> GatewayScope {
    match value {
        1 => GatewayScope::GatewaySdkRam,
        2 => GatewayScope::HostReceiveRam,
        other => panic!("bad gateway scope {other}"),
    }
}

/// The config_command "fields" spec: "id:type:valuehex,id:type:valuehex,...".
fn parse_fields_spec(spec: &str) -> Vec<ConfigField> {
    spec.split(',')
        .map(|entry| {
            let mut parts = entry.splitn(3, ':');
            let field_id = parts.next().and_then(|v| v.parse().ok()).expect("field id");
            let field_type = match parts
                .next()
                .and_then(|v| v.parse::<u8>().ok())
                .expect("field type")
            {
                1 => ConfigFieldType::Bool,
                2 => ConfigFieldType::U8,
                3 => ConfigFieldType::U32,
                4 => ConfigFieldType::Bytes,
                other => panic!("bad field type {other}"),
            };
            let value = hex_decode(parts.next().expect("field value"));
            ConfigField {
                field_id,
                field_type,
                value,
            }
        })
        .collect()
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/endpoint-golden")
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
        "scope_discover" => scope_discover_body_encode(&Rld1DiscoverBodyV2 {
            scope_class: scope_class(u64_field(fields, "scope_class")),
            generation: u64_field(fields, "generation") as u32,
            tag: arr16(fields, "tag_hex"),
        })
        .expect("scope_discover encode"),
        "scope_offer" => scope_offer_body_encode(&Rld1OfferBodyV2 {
            density: u64_field(fields, "density") as u8,
            cookie: arr16(fields, "cookie_hex"),
            responder_nonce: arr16(fields, "responder_nonce_hex"),
            scope_class: scope_class(u64_field(fields, "scope_class")),
            generation: u64_field(fields, "generation") as u32,
            tag: arr16(fields, "tag_hex"),
        })
        .expect("scope_offer encode"),
        "scope_binding" => scope_binding_encode(&ScopeBindingInput {
            scope_class: scope_class(u64_field(fields, "scope_class")),
            generation: u64_field(fields, "generation") as u32,
            scoped: u64_field(fields, "scoped") as u8,
            discover_digest: arr32(fields, "discover_digest_hex"),
            offer_digest: arr32(fields, "offer_digest_hex"),
        })
        .to_vec(),
        "scope_discover_mac_input" => scope_discover_mac_input(
            u64_field(fields, "network"),
            &mac(fields, "requester_mac_hex"),
            &mac(fields, "destination_mac_hex"),
            &hex_field(fields, "header_hex"),
            &hex_field(fields, "body_prefix_hex"),
        )
        .expect("discover mac input"),
        "scope_offer_mac_input" => scope_offer_mac_input(
            u64_field(fields, "network"),
            &mac(fields, "requester_mac_hex"),
            &mac(fields, "responder_mac_hex"),
            &hex_field(fields, "discover_digest_hex"),
            &hex_field(fields, "header_hex"),
            &hex_field(fields, "body_prefix_hex"),
        )
        .expect("offer mac input"),
        "service_query" => {
            service_query_encode(
                &ServiceQuery {
                    scope: scope(u64_field(fields, "scope")),
                    nonce: arr16(fields, "nonce_hex"),
                    expected_host_digest: arr32(fields, "expected_host_digest_hex"),
                },
                &mut out,
            )
            .expect("service_query encode");
            out.view().to_vec()
        }
        "service_descriptor" => {
            service_descriptor_encode(
                &ServiceDescriptor {
                    scope: scope(u64_field(fields, "scope")),
                    echo_nonce: arr16(fields, "echo_nonce_hex"),
                    token: arr16(fields, "token_hex"),
                    gateway_boot: u64_field(fields, "gateway_boot"),
                    host_digest: arr32(fields, "host_digest_hex"),
                    capabilities: u64_field(fields, "capabilities") as u32,
                    max_payload: u64_field(fields, "max_payload") as u16,
                    lease_ms: u64_field(fields, "lease_ms") as u32,
                },
                &mut out,
            )
            .expect("service_descriptor encode");
            out.view().to_vec()
        }
        "service_submit" => {
            service_submit_encode(
                &ServiceSubmit {
                    scope: scope(u64_field(fields, "scope")),
                    token: arr16(fields, "token_hex"),
                    gateway_boot: u64_field(fields, "gateway_boot"),
                    payload: hex_field(fields, "payload_hex"),
                },
                &mut out,
            )
            .expect("service_submit encode");
            out.view().to_vec()
        }
        "service_outcome" => {
            service_outcome_encode(
                &ServiceOutcome {
                    subtype: match u64_field(fields, "subtype") {
                        4 => ServiceSubtype::Receipt,
                        5 => ServiceSubtype::Pending,
                        6 => ServiceSubtype::Reject,
                        other => panic!("bad outcome subtype {other}"),
                    },
                    scope: scope(u64_field(fields, "scope")),
                    token: arr16(fields, "token_hex"),
                    gateway_boot: u64_field(fields, "gateway_boot"),
                    ref_origin: u64_field(fields, "ref_origin"),
                    ref_session: u64_field(fields, "ref_session") as u32,
                    ref_sequence: u64_field(fields, "ref_sequence"),
                    request_digest: arr32(fields, "request_digest_hex"),
                    reason: match u64_field(fields, "reason") {
                        0 => ServiceReason::Ok,
                        1 => ServiceReason::PendingWait,
                        2 => ServiceReason::TokenStale,
                        3 => ServiceReason::HostUnavailable,
                        4 => ServiceReason::Capacity,
                        5 => ServiceReason::RoleDenied,
                        6 => ServiceReason::Unsupported,
                        7 => ServiceReason::Deadline,
                        8 => ServiceReason::Conflict,
                        other => panic!("bad service reason {other}"),
                    },
                },
                &mut out,
            )
            .expect("service_outcome encode");
            out.view().to_vec()
        }
        "control_challenge_query" => {
            control_challenge_query_encode(
                &ControlChallengeQuery {
                    config_namespace: u64_field(fields, "config_namespace") as u16,
                    schema: u64_field(fields, "schema") as u16,
                    client_nonce: arr16(fields, "client_nonce_hex"),
                },
                &mut out,
            )
            .expect("control_challenge_query encode");
            out.view().to_vec()
        }
        "control_challenge" => {
            control_challenge_encode(
                &ControlChallenge {
                    config_namespace: u64_field(fields, "config_namespace") as u16,
                    schema: u64_field(fields, "schema") as u16,
                    client_nonce: arr16(fields, "client_nonce_hex"),
                    target_boot: u64_field(fields, "target_boot"),
                    challenge_nonce: arr16(fields, "challenge_nonce_hex"),
                    revision: u64_field(fields, "revision"),
                    active_hash: arr32(fields, "active_hash_hex"),
                    valid_for_ms: u64_field(fields, "valid_for_ms") as u32,
                },
                &mut out,
            )
            .expect("control_challenge encode");
            out.view().to_vec()
        }
        "control_status_query" => {
            control_status_query_encode(
                &ControlStatusQuery {
                    config_namespace: u64_field(fields, "config_namespace") as u16,
                    operation_id: arr16(fields, "operation_id_hex"),
                },
                &mut out,
            )
            .expect("control_status_query encode");
            out.view().to_vec()
        }
        "control_status" => {
            control_status_encode(
                &ControlStatus {
                    config_namespace: u64_field(fields, "config_namespace") as u16,
                    operation_id: arr16(fields, "operation_id_hex"),
                    decision_revision: u64_field(fields, "decision_revision"),
                    active_revision: u64_field(fields, "active_revision"),
                    phase: match u64_field(fields, "phase") {
                        0 => ConfigPhase::Idle,
                        1 => ConfigPhase::Prepared,
                        2 => ConfigPhase::Decided,
                        3 => ConfigPhase::ApplyIntent,
                        4 => ConfigPhase::Applying,
                        5 => ConfigPhase::Verifying,
                        6 => ConfigPhase::Active,
                        7 => ConfigPhase::Interrupted,
                        8 => ConfigPhase::Quarantined,
                        other => panic!("bad phase {other}"),
                    },
                    reason: match u64_field(fields, "reason") {
                        0 => ConfigReason::Ok,
                        1 => ConfigReason::InProgress,
                        2 => ConfigReason::StaleRevision,
                        3 => ConfigReason::BaseHashMismatch,
                        4 => ConfigReason::InvalidPatch,
                        5 => ConfigReason::Deadline,
                        6 => ConfigReason::AuthorityDenied,
                        7 => ConfigReason::Unsupported,
                        8 => ConfigReason::Capacity,
                        9 => ConfigReason::StorageFailure,
                        10 => ConfigReason::ApplyInterrupted,
                        11 => ConfigReason::VerifyFailed,
                        12 => ConfigReason::RecoveryRequired,
                        13 => ConfigReason::MaintenanceBusy,
                        14 => ConfigReason::NoChange,
                        15 => ConfigReason::ResultExpired,
                        other => panic!("bad config reason {other}"),
                    },
                    active_hash: arr32(fields, "active_hash_hex"),
                },
                &mut out,
            )
            .expect("control_status encode");
            out.view().to_vec()
        }
        "config_command" => {
            let mut raw = Vec::new();
            config_command_encode(
                &ConfigCommand {
                    config_namespace: u64_field(fields, "config_namespace") as u16,
                    schema: u64_field(fields, "schema") as u16,
                    network: u64_field(fields, "network"),
                    target: u64_field(fields, "target"),
                    authority: u64_field(fields, "authority"),
                    authority_generation: u64_field(fields, "authority_generation") as u32,
                    authority_sequence: u64_field(fields, "authority_sequence"),
                    operation_id: arr16(fields, "operation_id_hex"),
                    expected_revision: u64_field(fields, "expected_revision"),
                    next_revision: u64_field(fields, "next_revision"),
                    base_snapshot_hash: arr32(fields, "base_snapshot_hash_hex"),
                    next_snapshot_hash: arr32(fields, "next_snapshot_hash_hex"),
                    target_boot: u64_field(fields, "target_boot"),
                    challenge_nonce: arr16(fields, "challenge_nonce_hex"),
                    apply_within_ms: u64_field(fields, "apply_within_ms") as u32,
                    fields: parse_fields_spec(fields.get("fields").expect("fields")),
                },
                &mut raw,
            )
            .expect("config_command encode");
            raw
        }
        "config_snapshot_input" => config_snapshot_hash_input(
            u64_field(fields, "config_namespace") as u16,
            u64_field(fields, "schema") as u16,
            &hex_field(fields, "snapshot_hex"),
        )
        .expect("config snapshot input"),
        other => panic!("unknown codec {other}"),
    }
}

fn decode_vector(codec: &str, encoded: &[u8]) -> Result<(), String> {
    match codec {
        "scope_discover" => scope_discover_body_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "scope_offer" => scope_offer_body_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "service_query" => service_query_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "service_descriptor" => service_descriptor_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "service_submit" => service_submit_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "service_outcome" => service_outcome_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "control_challenge_query" => control_challenge_query_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "control_challenge" => control_challenge_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "control_status_query" => control_status_query_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "control_status" => control_status_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "config_command" => config_command_decode(encoded)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        // Encode-only canonical helpers have no decoder to run.
        "scope_binding"
        | "scope_discover_mac_input"
        | "scope_offer_mac_input"
        | "config_snapshot_input" => Ok(()),
        other => panic!("unknown codec {other}"),
    }
}

#[test]
fn valid_vectors_encode_and_decode_byte_exact() {
    let dir = golden_dir().join("valid");
    let files = list_json(&dir);
    assert!(files.len() >= 15, "expected at least 15 valid vectors");
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
    assert!(files.len() >= 15, "expected at least 15 invalid vectors");
    for path in files {
        let text = fs::read_to_string(&path).expect("read vector");
        let fields = parse_flat_json(&text);
        let name = fields.get("name").cloned().unwrap_or_default();
        let codec = fields.get("codec").expect("codec").as_str();
        let encoded = hex_field(&fields, "encoded_hex");
        assert!(
            decode_vector(codec, &encoded).is_err(),
            "{name}: unexpectedly decoded"
        );
    }
}

/// Every valid vector must still reject with one trailing byte appended:
/// decoders consume exactly their frame — leftover bytes are a framing
/// violation, never ignorable padding. Mirrors the same check in
/// tests/cpp/test_endpoint.cpp.
#[test]
fn trailing_byte_is_rejected() {
    let dir = golden_dir().join("valid");
    for path in list_json(&dir) {
        let text = fs::read_to_string(&path).expect("read vector");
        let fields = parse_flat_json(&text);
        let name = fields.get("name").cloned().unwrap_or_default();
        let codec = fields.get("codec").expect("codec").as_str();
        // Encode-only canonical helpers have no decoder to feed.
        if matches!(
            codec,
            "scope_binding"
                | "scope_discover_mac_input"
                | "scope_offer_mac_input"
                | "config_snapshot_input"
        ) {
            continue;
        }
        let mut encoded = hex_field(&fields, "encoded_hex");
        encoded.push(0x00);
        assert!(
            decode_vector(codec, &encoded).is_err(),
            "{name}: accepted a trailing 0x00"
        );
    }
}

#[test]
fn snapshot_encode_rejects_over_sixteen_fields() {
    // The C++ encoder refuses count > 16 outright; the Rust bare-TLV path
    // shared the field validator but skipped the count bound, so a
    // host-encoded snapshot could diverge from what the device accepts.
    let fields: Vec<ConfigField> = (1..=17)
        .map(|id| ConfigField {
            field_id: id,
            field_type: ConfigFieldType::U8,
            value: vec![id as u8],
        })
        .collect();
    assert!(config_tlv_encode(&fields).is_err());
    assert!(config_tlv_encode(&fields[..16]).is_ok());
}

#[test]
fn command_encode_rejects_broadcast_target_and_authority() {
    // target/authority are logical unicast ids: 0 and u64::MAX (broadcast)
    // are both reserved — the C++ codec refuses both, so the host side
    // must agree or a broadcast-addressed permit would leave the station.
    let mut command = ConfigCommand {
        config_namespace: 1,
        schema: 1,
        network: 7,
        target: 0x11,
        authority: 0x42,
        authority_generation: 1,
        authority_sequence: 1,
        operation_id: [1; 16],
        expected_revision: 0,
        next_revision: 1,
        base_snapshot_hash: [0; 32],
        next_snapshot_hash: [0; 32],
        target_boot: 1,
        challenge_nonce: [2; 16],
        apply_within_ms: 1000,
        fields: vec![ConfigField {
            field_id: 1,
            field_type: ConfigFieldType::U8,
            value: vec![1],
        }],
    };
    let mut out = Vec::new();
    assert!(config_command_encode(&command, &mut out).is_ok());
    command.target = u64::MAX;
    assert!(config_command_encode(&command, &mut out).is_err());
    command.target = 0x11;
    command.authority = u64::MAX;
    assert!(config_command_encode(&command, &mut out).is_err());
}
