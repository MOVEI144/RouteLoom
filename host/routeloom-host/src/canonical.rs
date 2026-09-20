//! Send-request validation and canonical serialization (Issue #8 / TX-I1).
//!
//! `parse_submit` validates one `messages.submit` params object: unknown
//! fields, wrong types and out-of-range values are rejected before any state
//! is touched. `admission_check` then enforces the capability line —
//! known-but-unimplemented values (APPLIED delivery, non-NORMAL priority,
//! sleep persistence, durable storage without a durable store) fail as
//! UNSUPPORTED, never silently downgrade. The two stages are split so the
//! canonical-serialization tests can check hash vectors for requests the
//! daemon refuses to admit.
//!
//! Canonical form (03-send-api.md §3): schema:u8=1, network:u32,
//! destination_kind:u8, destination:u64, delivery:u8, priority:u8,
//! deadline_policy:u8, storage:u8, ttl:u32, hop:u8, persist_sleep:u8,
//! payload_len:u16, payload — 26+payload bytes, big-endian. SHA-256 over
//! those bytes is the conflict-comparison identity alongside the caller key.
//! JSON field order, request_id, hex case and omitted-vs-explicit defaults
//! never affect the bytes.

use crate::acl;
use routeloom_json::Json;

// contracts.json `send.*` + 03-send-api.md §2 options table.
pub const TTL_DEFAULT_MS: u32 = 5000;
pub const TTL_MIN_MS: u32 = 1;
pub const TTL_MAX_MS: u32 = 30_000;
pub const HOP_DEFAULT: u8 = 10;
pub const HOP_MIN: u8 = 1;
pub const HOP_MAX: u8 = 10;
pub const SCHEMA_VERSION: u8 = 1;

// Canonical byte values.
pub const DEST_NODE: u8 = 0;
pub const DEST_GATEWAY: u8 = 1;
pub const DELIVERY_BEST_EFFORT: u8 = 0;
pub const DELIVERY_RELIABLE: u8 = 1;
pub const DELIVERY_APPLIED: u8 = 2;
pub const PRIORITY_BULK: u8 = 0;
pub const PRIORITY_NORMAL: u8 = 1;
pub const PRIORITY_MANAGEMENT: u8 = 2;
pub const PRIORITY_URGENT: u8 = 3;
pub const POLICY_WALL_ELAPSED: u8 = 0;
pub const STORAGE_RAM: u8 = 0;
pub const STORAGE_DURABLE: u8 = 1;

/// One validated submit: normalized fields plus the canonical bytes and
/// their SHA-256. `storage`/`delivery`/etc. keep the requested values even
/// when this phase cannot admit them — `admission_check` decides that.
#[derive(Debug)]
pub struct SendRequest {
    pub network: u64,
    pub epoch: u64,
    pub key: [u8; 16],
    pub dest_kind: u8,
    pub dest: u64,
    pub delivery: u8,
    pub priority: u8,
    pub ttl_ms: u32,
    pub storage: u8,
    pub hop_limit: u8,
    pub payload: Vec<u8>,
    pub canonical: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(Debug)]
pub struct SubmitReject {
    pub code: &'static str,
    pub message: String,
}

impl SubmitReject {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "INVALID_ARGUMENT",
            message: message.into(),
        }
    }
    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            code: "UNSUPPORTED",
            message: message.into(),
        }
    }
}

pub fn delivery_name(value: u8) -> &'static str {
    match value {
        DELIVERY_BEST_EFFORT => "BEST_EFFORT",
        DELIVERY_RELIABLE => "RELIABLE",
        _ => "APPLIED",
    }
}

pub fn priority_name(value: u8) -> &'static str {
    match value {
        PRIORITY_BULK => "BULK",
        PRIORITY_NORMAL => "NORMAL",
        PRIORITY_MANAGEMENT => "MANAGEMENT",
        _ => "URGENT",
    }
}

pub fn storage_name(value: u8) -> &'static str {
    match value {
        STORAGE_RAM => "RAM_ONLY",
        _ => "HOST_DURABLE",
    }
}

pub fn dest_kind_name(value: u8) -> &'static str {
    match value {
        DEST_GATEWAY => "gateway",
        _ => "node",
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect()
}

/// Reserved wire addresses excluded everywhere (01 §6): the API1
/// destination parser and the legacy SEND verb share this predicate so
/// both paths agree on the same rule.
pub fn is_reserved_node_id(value: u64) -> bool {
    value == 0 || value == u64::MAX
}

/// 16-hex node id; 0 and u64::MAX are excluded wire addresses (01 §6).
pub fn parse_node_hex(text: &str) -> Result<u64, String> {
    let raw = decode_hex(text).filter(|b| b.len() == 8);
    let Some(raw) = raw else {
        return Err(format!("\"{text}\" is not a 16-hex id"));
    };
    let value = u64::from_be_bytes(raw.try_into().expect("8 bytes"));
    if is_reserved_node_id(value) {
        return Err(format!("\"{text}\" is a reserved node id"));
    }
    Ok(value)
}

pub fn parse_key_hex(text: &str) -> Result<[u8; 16], String> {
    let raw = decode_hex(text).filter(|b| b.len() == 16);
    let Some(raw) = raw else {
        return Err(format!("\"{text}\" is not a 32-hex idempotency key"));
    };
    Ok(raw.try_into().expect("16 bytes"))
}

pub fn parse_epoch_hex(text: &str) -> Result<u64, String> {
    let raw = decode_hex(text).filter(|b| b.len() == 8);
    let Some(raw) = raw else {
        return Err(format!("\"{text}\" is not a 16-hex epoch"));
    };
    let value = u64::from_be_bytes(raw.try_into().expect("8 bytes"));
    if value == 0 || value == u64::MAX {
        return Err("admission_epoch is in the reserved range".to_string());
    }
    Ok(value)
}

/// Schema + type + range validation. Defaults are filled before the
/// canonical bytes are built, so omitted-vs-explicit defaults hash alike.
pub fn parse_submit(params: &Json) -> Result<SendRequest, SubmitReject> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "network"
                | "admission_epoch"
                | "key"
                | "destination"
                | "payload_hex"
                | "payload_len"
                | "options"
        ) {
            return Err(SubmitReject::invalid(format!("unknown param \"{key}\"")));
        }
    }
    let network = match params.get("network").and_then(Json::as_str) {
        Some(text) => acl::parse_network_hex(text).map_err(SubmitReject::invalid)?,
        None => return Err(SubmitReject::invalid("network must be a 16-hex string")),
    };
    let epoch = match params.get("admission_epoch").and_then(Json::as_str) {
        Some(text) => parse_epoch_hex(text).map_err(SubmitReject::invalid)?,
        None => {
            return Err(SubmitReject::invalid(
                "admission_epoch must be a 16-hex string",
            ))
        }
    };
    let key = match params.get("key").and_then(Json::as_str) {
        Some(text) => parse_key_hex(text).map_err(SubmitReject::invalid)?,
        None => return Err(SubmitReject::invalid("key must be a 32-hex string")),
    };
    let (dest_kind, dest) = parse_destination(params.get("destination"))?;
    let payload = parse_payload(params.get("payload_hex"), params.get("payload_len"))?;
    let (delivery, priority, ttl_ms, storage, hop_limit) = parse_options(params.get("options"))?;
    let canonical = canonical_bytes(
        network as u32,
        dest_kind,
        dest,
        delivery,
        priority,
        storage,
        ttl_ms,
        hop_limit,
        &payload,
    );
    let hash = sha256(&canonical);
    Ok(SendRequest {
        network,
        epoch,
        key,
        dest_kind,
        dest,
        delivery,
        priority,
        ttl_ms,
        storage,
        hop_limit,
        payload,
        canonical,
        hash,
    })
}

fn parse_destination(value: Option<&Json>) -> Result<(u8, u64), SubmitReject> {
    let Some(value) = value else {
        return Err(SubmitReject::invalid("destination is required"));
    };
    if !matches!(value, Json::Object(_)) {
        return Err(SubmitReject::invalid("destination must be an object"));
    }
    for (key, _) in value.object_entries() {
        if !matches!(key.as_str(), "kind" | "id") {
            return Err(SubmitReject::invalid(format!(
                "unknown destination field \"{key}\""
            )));
        }
    }
    let kind = match value.get("kind").and_then(Json::as_str) {
        Some("node") => DEST_NODE,
        Some("gateway") => DEST_GATEWAY,
        Some(_) => {
            return Err(SubmitReject::invalid(
                "destination.kind must be \"node\" or \"gateway\"",
            ))
        }
        None => return Err(SubmitReject::invalid("destination.kind is required")),
    };
    let dest = match value.get("id").and_then(Json::as_str) {
        Some(text) => parse_node_hex(text).map_err(SubmitReject::invalid)?,
        None => return Err(SubmitReject::invalid("destination.id is required")),
    };
    Ok((kind, dest))
}

fn parse_payload(hex: Option<&Json>, len: Option<&Json>) -> Result<Vec<u8>, SubmitReject> {
    let Some(text) = hex.and_then(Json::as_str) else {
        return Err(SubmitReject::invalid("payload_hex must be a string"));
    };
    let Some(bytes) = decode_hex(text) else {
        return Err(SubmitReject::invalid("payload_hex must be even-length hex"));
    };
    let Some(declared) = len.and_then(Json::as_u64) else {
        return Err(SubmitReject::invalid("payload_len must be an integer"));
    };
    if declared != bytes.len() as u64 {
        return Err(SubmitReject::invalid(
            "payload_len does not match payload_hex bytes",
        ));
    }
    if bytes.len() > crate::receive_log::NORMAL_PAYLOAD_MAX {
        return Err(SubmitReject {
            code: "PAYLOAD_TOO_LARGE",
            message: format!(
                "payload exceeds {} bytes",
                crate::receive_log::NORMAL_PAYLOAD_MAX
            ),
        });
    }
    Ok(bytes)
}

/// Options with contract defaults filled. Unknown keys and wrong types
/// reject here; known-but-unimplemented values reject in `admission_check`.
#[allow(clippy::type_complexity)]
fn parse_options(value: Option<&Json>) -> Result<(u8, u8, u32, u8, u8), SubmitReject> {
    let value = match value {
        None | Some(Json::Null) => return Ok(default_options()),
        Some(value @ Json::Object(_)) => value,
        Some(_) => return Err(SubmitReject::invalid("options must be an object")),
    };
    for (key, _) in value.object_entries() {
        if !matches!(
            key.as_str(),
            "delivery"
                | "priority"
                | "ttl_ms"
                | "deadline_policy"
                | "storage"
                | "hop_limit"
                | "persist_across_sleep"
        ) {
            return Err(SubmitReject::invalid(format!("unknown option \"{key}\"")));
        }
    }
    let delivery = match value.get("delivery") {
        None => DELIVERY_RELIABLE,
        Some(Json::String(name)) => match name.as_str() {
            "BEST_EFFORT" => DELIVERY_BEST_EFFORT,
            "RELIABLE" => DELIVERY_RELIABLE,
            "APPLIED" => DELIVERY_APPLIED,
            _ => return Err(SubmitReject::invalid("unknown delivery value")),
        },
        Some(_) => return Err(SubmitReject::invalid("delivery must be a string")),
    };
    let priority = match value.get("priority") {
        None => PRIORITY_NORMAL,
        Some(Json::String(name)) => match name.as_str() {
            "BULK" => PRIORITY_BULK,
            "NORMAL" => PRIORITY_NORMAL,
            "MANAGEMENT" => PRIORITY_MANAGEMENT,
            "URGENT" => PRIORITY_URGENT,
            _ => return Err(SubmitReject::invalid("unknown priority value")),
        },
        Some(_) => return Err(SubmitReject::invalid("priority must be a string")),
    };
    let ttl_ms = match value.get("ttl_ms") {
        None => TTL_DEFAULT_MS,
        Some(number) => match number.as_u64() {
            Some(ms) if (u64::from(TTL_MIN_MS)..=u64::from(TTL_MAX_MS)).contains(&ms) => ms as u32,
            _ => {
                return Err(SubmitReject::invalid(format!(
                    "ttl_ms must be an integer {TTL_MIN_MS}..={TTL_MAX_MS}"
                )))
            }
        },
    };
    match value.get("deadline_policy") {
        None => {}
        Some(Json::String(name)) if name == "WALL_ELAPSED_VALIDITY" => {}
        Some(Json::String(_)) => {
            return Err(SubmitReject::invalid(
                "deadline_policy must be \"WALL_ELAPSED_VALIDITY\"",
            ))
        }
        Some(_) => return Err(SubmitReject::invalid("deadline_policy must be a string")),
    }
    let storage = match value.get("storage") {
        None => STORAGE_DURABLE,
        Some(Json::String(name)) => match name.as_str() {
            "RAM_ONLY" => STORAGE_RAM,
            "HOST_DURABLE" => STORAGE_DURABLE,
            _ => return Err(SubmitReject::invalid("unknown storage value")),
        },
        Some(_) => return Err(SubmitReject::invalid("storage must be a string")),
    };
    let hop_limit = match value.get("hop_limit") {
        None => HOP_DEFAULT,
        Some(number) => match number.as_u64() {
            Some(hop) if (u64::from(HOP_MIN)..=u64::from(HOP_MAX)).contains(&hop) => hop as u8,
            _ => {
                return Err(SubmitReject::invalid(format!(
                    "hop_limit must be an integer {HOP_MIN}..={HOP_MAX}"
                )))
            }
        },
    };
    match value.get("persist_across_sleep") {
        None => {}
        Some(Json::Bool(_)) => {}
        Some(_) => {
            return Err(SubmitReject::invalid(
                "persist_across_sleep must be a boolean",
            ))
        }
    }
    Ok((delivery, priority, ttl_ms, storage, hop_limit))
}

#[allow(clippy::type_complexity)]
fn default_options() -> (u8, u8, u32, u8, u8) {
    (
        DELIVERY_RELIABLE,
        PRIORITY_NORMAL,
        TTL_DEFAULT_MS,
        STORAGE_DURABLE,
        HOP_DEFAULT,
    )
}

/// Capability gate after schema validation. Every rejection here names the
/// missing capability instead of falling back to a weaker behavior.
/// `store_durable` is the bound operation store's durability: HOST_DURABLE
/// submits are admitted only where the store retains them across restarts.
pub fn admission_check(
    req: &SendRequest,
    persist_sleep: bool,
    store_durable: bool,
) -> Result<(), SubmitReject> {
    if req.delivery == DELIVERY_APPLIED {
        return Err(SubmitReject::unsupported(
            "delivery APPLIED is not enabled in this phase",
        ));
    }
    if req.priority != PRIORITY_NORMAL {
        return Err(SubmitReject::unsupported(
            "only priority NORMAL is enabled in this phase",
        ));
    }
    if req.storage == STORAGE_DURABLE && !store_durable {
        return Err(SubmitReject::unsupported(
            "storage HOST_DURABLE needs a durable operation store; pass storage RAM_ONLY for in-memory acceptance",
        ));
    }
    if persist_sleep {
        return Err(SubmitReject::unsupported(
            "persist_across_sleep=true is not supported by this Host API",
        ));
    }
    Ok(())
}

/// Whether the parsed options asked for sleep persistence (kept out of
/// `SendRequest` — the canonical bytes fix the field to 0 in this phase).
pub fn wants_persist_sleep(params: &Json) -> bool {
    params
        .get("options")
        .and_then(|o| o.get("persist_across_sleep"))
        .and_then(Json::as_bool)
        .unwrap_or(false)
}

/// Fixed-order big-endian encoding per 03-send-api.md §3.
#[allow(clippy::too_many_arguments)]
pub fn canonical_bytes(
    network: u32,
    dest_kind: u8,
    dest: u64,
    delivery: u8,
    priority: u8,
    storage: u8,
    ttl_ms: u32,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(26 + payload.len());
    out.push(SCHEMA_VERSION);
    out.extend_from_slice(&network.to_be_bytes());
    out.push(dest_kind);
    out.extend_from_slice(&dest.to_be_bytes());
    out.push(delivery);
    out.push(priority);
    out.push(POLICY_WALL_ELAPSED);
    out.push(storage);
    out.extend_from_slice(&ttl_ms.to_be_bytes());
    out.push(hop_limit);
    out.push(0); // persist_sleep: only false is admittable in this phase
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `OperationId` wire form: `<32-hex store lineage>:<16-hex sequence>`.
pub fn format_operation_id(lineage: &[u8; 16], seq: u64) -> String {
    format!("{}:{seq:016x}", crate::receive_log::hex_lower(lineage))
}

pub fn parse_operation_id(text: &str) -> Option<([u8; 16], u64)> {
    let (lineage_hex, seq_hex) = text.split_once(':')?;
    let lineage = decode_hex(lineage_hex).filter(|b| b.len() == 16)?;
    let seq_raw = decode_hex(seq_hex).filter(|b| b.len() == 8)?;
    if seq_raw == [0; 8] {
        return None; // sequence 0 is never issued
    }
    Some((
        lineage.try_into().expect("16 bytes"),
        u64::from_be_bytes(seq_raw.try_into().expect("8 bytes")),
    ))
}

// SHA-256 (FIPS 180-4), std-only: the workspace carries no hash crate and
// the canonical hash must not depend on one.
const SHA_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut padded = Vec::with_capacity((message.len() + 9).div_ceil(64) * 64);
    padded.extend_from_slice(message);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((message.len() as u64).wrapping_mul(8)).to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("4"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (v, delta) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *v = v.wrapping_add(delta);
        }
    }
    let mut out = [0_u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive_log::hex_lower;

    fn submit_params(json: &str) -> Json {
        routeloom_json::parse(json).unwrap()
    }

    #[test]
    fn sha256_matches_classic_vector() {
        assert_eq!(
            hex_lower(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_lower(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// fixtures.json `valid_send`: byte-exact canonical form and hash.
    /// Parsed without the admission gate — the fixtures use the
    /// HOST_DURABLE default this phase refuses to admit.
    #[test]
    fn fixtures_canonical_and_hash() {
        let cases = [
            (
                "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0}",
                "010000000100000000000000000301010001000013880a000000",
                "c3a00776c0a2c8a4aa29041f9d7814f913aa57d6f9747b35ce46cd191b418a7e",
            ),
            (
                "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00FF80\",\"payload_len\":3,\"options\":{\"delivery\":\"RELIABLE\",\"priority\":\"NORMAL\",\"ttl_ms\":5000,\"deadline_policy\":\"WALL_ELAPSED_VALIDITY\",\"storage\":\"HOST_DURABLE\",\"hop_limit\":10}}",
                "010000000100000000000000000301010001000013880a00000300ff80",
                "771436a0c33cb753408fd2aca95f3d5862d4b27197a2e93c98483e847578f0fa",
            ),
        ];
        for (json, canonical_hex, hash_hex) in cases {
            let req = parse_submit(&submit_params(json)).expect(json);
            assert_eq!(hex_lower(&req.canonical), canonical_hex, "{json}");
            assert_eq!(hex_lower(&req.hash), hash_hex, "{json}");
            assert_eq!(req.canonical.len(), 26 + req.payload.len());
        }
        // Maximum payload (128B of 00..7f) — built, not pasted.
        let payload: Vec<u8> = (0..128_u32).map(|b| b as u8).collect();
        let json = format!(
            "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"{}\",\"payload_len\":128}}",
            hex_lower(&payload)
        );
        let req = parse_submit(&submit_params(&json)).unwrap();
        let mut expected = String::from("010000000100000000000000000301010001000013880a000080");
        expected.push_str(&hex_lower(&payload));
        assert_eq!(hex_lower(&req.canonical), expected);
        assert_eq!(
            hex_lower(&req.hash),
            "d6316a8dd2350a69a53b1a606dc7e53911026a8abecc428319083dd6f482cf2d"
        );
    }

    /// TX01: field order, hex case and omitted-vs-explicit defaults hash alike.
    #[test]
    fn canonical_is_order_and_case_independent() {
        let a = "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00FF80\",\"payload_len\":3}";
        let b = "{\"payload_len\":3,\"payload_hex\":\"00ff80\",\"key\":\"00112233445566778899AABBCCDDEEFF\",\"destination\":{\"id\":\"0000000000000003\",\"kind\":\"node\"},\"admission_epoch\":\"0000000000000012\",\"network\":\"0000000000000001\",\"options\":{\"hop_limit\":10,\"ttl_ms\":5000,\"storage\":\"HOST_DURABLE\",\"deadline_policy\":\"WALL_ELAPSED_VALIDITY\",\"priority\":\"NORMAL\",\"delivery\":\"RELIABLE\"}}";
        let ra = parse_submit(&submit_params(a)).unwrap();
        let rb = parse_submit(&submit_params(b)).unwrap();
        assert_eq!(ra.canonical, rb.canonical);
        assert_eq!(ra.hash, rb.hash);
    }

    #[test]
    fn distinct_requests_hash_distinctly() {
        let base = "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00\",\"payload_len\":1}";
        let other = "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"01\",\"payload_len\":1}";
        let (a, b) = (
            parse_submit(&submit_params(base)).unwrap(),
            parse_submit(&submit_params(other)).unwrap(),
        );
        assert_ne!(a.hash, b.hash);
        // The caller key and epoch are identity, not hash input: same body
        // under another key hashes the same and conflicts by comparison.
        let rekeyed = "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000013\",\"key\":\"ffffffffffffffffffffffffffffffff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00\",\"payload_len\":1}";
        let c = parse_submit(&submit_params(rekeyed)).unwrap();
        assert_eq!(a.canonical, c.canonical);
    }

    /// fixtures.json `invalid_send` mapped onto API1 error codes.
    #[test]
    fn invalid_fixtures_reject() {
        let base = |extra: &str| {
            format!(
                "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0{extra}}}"
            )
        };
        // Parse-stage rejects (INVALID_ARGUMENT / PAYLOAD_TOO_LARGE).
        let invalid_params = [
            base(",\"options\":{\"ttl_ms\":0}"),
            base(",\"options\":{\"ttl_ms\":30001}"),
            base(",\"options\":{\"ttl_ms\":true}"),
            base(",\"options\":{\"ttl_ms\":5000.0}"),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":-1}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"f\",\"payload_len\":1}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"zz\",\"payload_len\":1}".to_string(),
            base(",\"principal\":\"admin\""),
            base(",\"options\":{\"delivery\":\"APPLIED\",\"bogus\":1}"),
            base(",\"options\":{\"hop_limit\":0}"),
            base(",\"options\":{\"hop_limit\":11}"),
            base(",\"options\":{\"persist_across_sleep\":\"yes\"}"),
            base(",\"options\":{\"deadline_policy\":\"BEST_EFFORT\"}"),
            base(",\"options\":{\"storage\":\"RAM\"}"),
            base(",\"options\":{\"priority\":\"normal\"}"),
            base(",\"options\":[]"),
            "{\"network\":\"0000000100000000\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000000\"},\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"ffffffffffffffff\"},\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"short\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000000\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"anycast\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\",\"extra\":1},\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
            "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"payload_hex\":\"\",\"payload_len\":0}".to_string(),
        ];
        for json in invalid_params {
            let err = parse_submit(&submit_params(&json)).expect_err(&json);
            assert_eq!(err.code, "INVALID_ARGUMENT", "{json}: {}", err.message);
        }
        // Oversize (129B, consistent length) is its own class.
        let big = "00".repeat(129);
        let json = format!(
            "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"{big}\",\"payload_len\":129}}"
        );
        let err = parse_submit(&submit_params(&json)).unwrap_err();
        assert_eq!(err.code, "PAYLOAD_TOO_LARGE");
    }

    /// Known-but-unimplemented values pass the schema and fail admission.
    #[test]
    fn unsupported_options_reject_without_downgrade() {
        let base = |options: &str| {
            format!(
                "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{options}}}"
            )
        };
        // The HOST_DURABLE default is admittable only with a durable store.
        let defaulted = parse_submit(&submit_params(&base("{}"))).unwrap();
        assert_eq!(defaulted.storage, STORAGE_DURABLE);
        let err = admission_check(&defaulted, false, false).unwrap_err();
        assert_eq!(err.code, "UNSUPPORTED");
        assert!(admission_check(&defaulted, false, true).is_ok());
        for options in [
            "{\"delivery\":\"APPLIED\",\"storage\":\"RAM_ONLY\"}",
            "{\"priority\":\"URGENT\",\"storage\":\"RAM_ONLY\"}",
            "{\"priority\":\"BULK\",\"storage\":\"RAM_ONLY\"}",
            "{\"storage\":\"RAM_ONLY\",\"persist_across_sleep\":true}",
            "{\"storage\":\"HOST_DURABLE\"}",
        ] {
            let json = base(options);
            let req = parse_submit(&submit_params(&json)).expect(&json);
            let persist = wants_persist_sleep(&submit_params(&json));
            let err = admission_check(&req, persist, false).expect_err(&json);
            assert_eq!(err.code, "UNSUPPORTED", "{json}");
        }
        // BEST_EFFORT + RAM_ONLY is the admittable non-default mix.
        let json = base("{\"delivery\":\"BEST_EFFORT\",\"storage\":\"RAM_ONLY\"}");
        let req = parse_submit(&submit_params(&json)).unwrap();
        assert!(admission_check(&req, false, false).is_ok());
        // Gateway destination parses and encodes distinctly from node.
        let gw = "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000012\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"gateway\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{\"storage\":\"RAM_ONLY\"}}";
        let req = parse_submit(&submit_params(gw)).unwrap();
        assert_eq!(req.dest_kind, DEST_GATEWAY);
        assert_eq!(req.canonical[5], DEST_GATEWAY);
        assert!(admission_check(&req, false, false).is_ok());
    }

    #[test]
    fn operation_id_roundtrips_and_rejects_reserved() {
        let lineage = [0xabu8; 16];
        let id = format_operation_id(&lineage, 1);
        assert_eq!(id, "abababababababababababababababab:0000000000000001");
        assert_eq!(parse_operation_id(&id), Some((lineage, 1)));
        for bad in [
            "abab:0000000000000001",
            "abababababababababababababababab:0000000000000000",
            "abababababababababababababababab:000000000000000g",
            "abababababababababababababababab",
            "ABABABABABABABABABABABABABABABAB:0000000000000001:extra",
            "",
        ] {
            assert_eq!(parse_operation_id(bad), None, "{bad}");
        }
        // Uppercase hex parses (normalized by decoding, like all IPC hex).
        assert_eq!(
            parse_operation_id("ABABABABABABABABABABABABABABABAB:0000000000000001"),
            Some((lineage, 1))
        );
    }
}
