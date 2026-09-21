#!/usr/bin/env python3
"""Regenerate protocol/endpoint-golden/*.json for the scope-gateway-config
wire codec contract (docs/design/scope-gateway-config/05-wire-api.md).

The layouts mirror components/routeloom/src/endpoint_wire.cpp and
host/routeloom-wire/src/endpoint.rs. All integers are big-endian; reserved
bytes are 0. These vectors pin byte layouts only — no crypto claims
(production suite pending). Design example bytes from
docs/design/scope-gateway-config/{examples,config-example}.json are reused
verbatim where they exist so the codec is pinned to the design fixtures.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "endpoint-golden"
DESIGN = ROOT / "docs" / "design" / "scope-gateway-config"

def u8(v): return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)


# --- RLD1 body v2 -------------------------------------------------------------

def discover_body(scope_class, generation, tag):
    return u8(2) + u8(scope_class) + u8(1) + u8(0) + u32(generation) + tag


def offer_body(density, cookie, responder_nonce, scope_class, generation, tag):
    return (u8(2) + u8(density) + u16(0) + cookie + responder_nonce +
            u8(scope_class) + u8(1) + u16(0) + u32(generation) + tag)


HINT_DOMAIN = b"RouteLoom/DSK/v1/hint\0"
DISCOVER_DOMAIN = b"RouteLoom/DSK/v1/discover\0"
OFFER_DOMAIN = b"RouteLoom/DSK/v1/offer\0"
BINDING_DOMAIN = b"RouteLoom/DSK/v1/auth-binding\0"
SNAPSHOT_DOMAIN = b"RouteLoom/config-snapshot/v1\0"


def binding_input(scope_class, generation, scoped, discover_digest, offer_digest):
    return (u8(scope_class) + u32(generation) + u8(1) + u8(scoped) +
            discover_digest + offer_digest)


def discover_mac_input(network, requester, destination, header, prefix):
    return DISCOVER_DOMAIN + u64(network) + requester + destination + header + prefix


def offer_mac_input(network, requester, responder, digest, header, prefix):
    return OFFER_DOMAIN + u64(network) + requester + responder + digest + header + prefix


# --- Service=21 ---------------------------------------------------------------

def service_preamble(sub, scope):
    return u8(1) + u8(sub) + u8(scope) + u8(0)


def service_query(scope, nonce, digest):
    return service_preamble(1, scope) + nonce + digest


def service_descriptor(scope, echo, token, boot, digest, caps, max_payload, lease):
    return (service_preamble(2, scope) + echo + token + u64(boot) + digest +
            u32(caps) + u16(max_payload) + u32(lease))


def service_submit(scope, token, boot, payload, flags=0, reserved=0, declared=None):
    if declared is None:
        declared = len(payload)
    return (service_preamble(3, scope)[:3] + u8(flags) + token + u64(boot) +
            u16(declared) + u16(reserved) + payload)


def service_outcome(sub, scope, token, boot, ref_origin, ref_session,
                    ref_sequence, digest, reason, reserved=0):
    return (service_preamble(sub, scope) + token + u64(boot) + u64(ref_origin) +
            u32(ref_session) + u64(ref_sequence) + digest + u16(reason) +
            u16(reserved))


# --- Control=22 ---------------------------------------------------------------

def control_cq(ns, schema, client_nonce, reserved=0):
    return u8(1) + u8(1) + u16(ns) + u16(schema) + u16(reserved) + client_nonce


def control_challenge(ns, schema, client_nonce, boot, challenge_nonce, revision,
                      active_hash, valid_for_ms):
    return (u8(1) + u8(2) + u16(ns) + u16(schema) + u16(0) + client_nonce +
            u64(boot) + challenge_nonce + u64(revision) + active_hash +
            u32(valid_for_ms))


def control_sq(ns, opid):
    return u8(1) + u8(3) + u16(ns) + opid


def control_status(ns, opid, decision_rev, active_rev, phase, reason,
                   active_hash, reserved=0):
    return (u8(1) + u8(4) + u16(ns) + opid + u64(decision_rev) +
            u64(active_rev) + u8(phase) + u8(reserved) + u16(reason) +
            active_hash)


# --- RCC1 ---------------------------------------------------------------------

def tlv(field_id, field_type, value):
    return u16(field_id) + u8(field_type) + u16(len(value)) + value


def rcc1(ns, schema, field_count, network, target, authority, auth_gen,
         auth_seq, opid, expected, nxt, base_hash, next_hash, target_boot,
         challenge_nonce, apply_ms, patch, version=1, flags=0, reserved=0,
         patch_len=None, magic=b"RCC1"):
    if patch_len is None:
        patch_len = len(patch)
    return (magic + u8(version) + u8(flags) + u16(ns) + u16(schema) +
            u16(field_count) + u64(network) + u64(target) + u64(authority) +
            u32(auth_gen) + u64(auth_seq) + opid + u64(expected) + u64(nxt) +
            base_hash + next_hash + u64(target_boot) + challenge_nonce +
            u32(apply_ms) + u16(patch_len) + u16(reserved) + patch)


def emit(folder, name, record):
    path = OUT / folder / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def main():
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)

    fmt = "routeloom-endpoint-v1-golden"
    ex = json.loads((DESIGN / "examples.json").read_text())
    cf = json.loads((DESIGN / "config-example.json").read_text())

    # Design fixtures (docs/design/scope-gateway-config/examples.json).
    discover_packet = bytes.fromhex(ex["scope"]["discover_hex"])
    offer_packet = bytes.fromhex(ex["scope"]["offer_hex"])
    discover_body_bytes = discover_packet[44:]
    offer_body_bytes = offer_packet[44:]
    requester = bytes.fromhex(ex["scope"]["requester_mac_hex"])
    responder = bytes.fromhex(ex["scope"]["responder_mac_hex"])
    broadcast = b"\xff" * 6
    discover_digest = bytes.fromhex(ex["scope"]["discover_digest_hex"])
    offer_digest = bytes.fromhex(ex["scope"]["offer_digest_hex"])

    nonce = bytes(range(16))             # 00..0f
    token = b"1" * 16
    digest32 = bytes(range(32))
    opid = b"5" * 16

    valid = []
    # Scope bodies — pinned to the design example bytes.
    valid.append(("scope_discover_v2", "scope_discover", dict(
        scope_class=1, generation=7,
        tag_hex=discover_body_bytes[8:].hex()), discover_body_bytes))
    valid.append(("scope_offer_v2", "scope_offer", dict(
        density=1, cookie_hex="a5" * 16,
        responder_nonce_hex="101112131415161718191a1b1c1d1e1f",
        scope_class=1, generation=7,
        tag_hex=offer_body_bytes[44:].hex()), offer_body_bytes))
    valid.append(("scope_discover_v2_commissioning", "scope_discover", dict(
        scope_class=2, generation=9, tag_hex=nonce.hex()),
        discover_body(2, 9, nonce)))
    valid.append(("scope_binding", "scope_binding", dict(
        scope_class=1, generation=7, scoped=1,
        discover_digest_hex=discover_digest.hex(),
        offer_digest_hex=offer_digest.hex()),
        binding_input(1, 7, 1, discover_digest, offer_digest)))
    valid.append(("scope_discover_mac_input", "scope_discover_mac_input", dict(
        network=1, requester_mac_hex=requester.hex(),
        destination_mac_hex=broadcast.hex(),
        header_hex=discover_packet[:44].hex(),
        body_prefix_hex=discover_body_bytes[:8].hex()),
        discover_mac_input(1, requester, broadcast, discover_packet[:44],
                           discover_body_bytes[:8])))
    valid.append(("scope_offer_mac_input", "scope_offer_mac_input", dict(
        network=1, requester_mac_hex=requester.hex(),
        responder_mac_hex=responder.hex(),
        discover_digest_hex=discover_digest.hex(),
        header_hex=offer_packet[:44].hex(),
        body_prefix_hex=offer_body_bytes[:44].hex()),
        offer_mac_input(1, requester, responder, discover_digest,
                        offer_packet[:44], offer_body_bytes[:44])))

    # Service=21.
    valid.append(("service_query_sdk", "service_query", dict(
        scope=1, nonce_hex=nonce.hex(),
        expected_host_digest_hex="00" * 32),
        service_query(1, nonce, bytes(32))))
    valid.append(("service_query_host", "service_query", dict(
        scope=2, nonce_hex=nonce.hex(),
        expected_host_digest_hex=digest32.hex()),
        service_query(2, nonce, digest32)))
    valid.append(("service_descriptor_sdk", "service_descriptor", dict(
        scope=1, echo_nonce_hex=nonce.hex(), token_hex=token.hex(),
        gateway_boot=9, host_digest_hex="00" * 32, capabilities=3,
        max_payload=96, lease_ms=15000),
        service_descriptor(1, nonce, token, 9, bytes(32), 3, 96, 15000)))
    valid.append(("service_descriptor_host", "service_descriptor", dict(
        scope=2, echo_nonce_hex=nonce.hex(), token_hex=token.hex(),
        gateway_boot=9, host_digest_hex=digest32.hex(), capabilities=7,
        max_payload=96, lease_ms=15000),
        service_descriptor(2, nonce, token, 9, digest32, 7, 96, 15000)))
    # Submit vectors reuse the design examples byte-for-byte.
    for row in ex["gateway_submits"]:
        valid.append((f"service_submit_{row['id']}", "service_submit", dict(
            scope=2, token_hex=token.hex(), gateway_boot=9,
            payload_hex=row["payload_hex"]),
            bytes.fromhex(row["encoded_hex"])))
    valid.append(("service_receipt_ok", "service_outcome", dict(
        subtype=4, scope=2, token_hex=token.hex(), gateway_boot=9,
        ref_origin=0x22, ref_session=7, ref_sequence=99,
        request_digest_hex=digest32.hex(), reason=0),
        service_outcome(4, 2, token, 9, 0x22, 7, 99, digest32, 0)))
    valid.append(("service_pending_wait", "service_outcome", dict(
        subtype=5, scope=2, token_hex=token.hex(), gateway_boot=9,
        ref_origin=0x22, ref_session=7, ref_sequence=99,
        request_digest_hex=digest32.hex(), reason=1),
        service_outcome(5, 2, token, 9, 0x22, 7, 99, digest32, 1)))
    valid.append(("service_reject_capacity", "service_outcome", dict(
        subtype=6, scope=1, token_hex=token.hex(), gateway_boot=9,
        ref_origin=0x11, ref_session=3, ref_sequence=5,
        request_digest_hex=digest32.hex(), reason=4),
        service_outcome(6, 1, token, 9, 0x11, 3, 5, digest32, 4)))

    # Control=22.
    valid.append(("control_challenge_query", "control_challenge_query", dict(
        config_namespace=1, schema=1, client_nonce_hex=nonce.hex()),
        control_cq(1, 1, nonce)))
    valid.append(("control_challenge", "control_challenge", dict(
        config_namespace=1, schema=1, client_nonce_hex=nonce.hex(),
        target_boot=9, challenge_nonce_hex=opid.hex(), revision=7,
        active_hash_hex=digest32.hex(), valid_for_ms=30000),
        control_challenge(1, 1, nonce, 9, opid, 7, digest32, 30000)))
    valid.append(("control_challenge_query_appns", "control_challenge_query", dict(
        config_namespace=0x8001, schema=4, client_nonce_hex=nonce.hex()),
        control_cq(0x8001, 4, nonce)))
    valid.append(("control_status_query", "control_status_query", dict(
        config_namespace=1, operation_id_hex=opid.hex()),
        control_sq(1, opid)))
    valid.append(("control_status_active", "control_status", dict(
        config_namespace=1, operation_id_hex=opid.hex(), decision_revision=8,
        active_revision=8, phase=6, reason=0, active_hash_hex=digest32.hex()),
        control_status(1, opid, 8, 8, 6, 0, digest32)))

    # RCC1 — the design config-example is pinned verbatim.
    valid.append(("config_command", "config_command", dict(
        config_namespace=1, schema=1, network=1, target=0x30, authority=0x10,
        authority_generation=2, authority_sequence=13,
        operation_id_hex="55" * 16, expected_revision=7, next_revision=8,
        base_snapshot_hash_hex=cf["canonical_hex"][160:224],
        next_snapshot_hash_hex=cf["canonical_hex"][224:288],
        target_boot=9, challenge_nonce_hex="66" * 16, apply_within_ms=5000,
        fields="1:2:01,3:1:00"),
        bytes.fromhex(cf["canonical_hex"])))
    big = bytes(range(96))
    patch_all = tlv(1, 1, b"\x01") + tlv(5, 2, b"\xaa") + \
        tlv(9, 3, u32(0x01020304)) + tlv(12, 4, big)
    valid.append(("config_command_all_types", "config_command", dict(
        config_namespace=0x8001, schema=4, network=1, target=0x30,
        authority=0x10, authority_generation=2, authority_sequence=14,
        operation_id_hex=opid.hex(), expected_revision=8, next_revision=9,
        base_snapshot_hash_hex=digest32.hex(),
        next_snapshot_hash_hex=bytes(range(32, 64)).hex(),
        target_boot=9, challenge_nonce_hex=opid.hex(), apply_within_ms=30000,
        fields="1:1:01,5:2:aa,9:3:01020304,12:4:" + big.hex()),
        rcc1(0x8001, 4, 4, 1, 0x30, 0x10, 2, 14, opid, 8, 9, digest32,
             bytes(range(32, 64)), 9, opid, 30000, patch_all)))
    valid.append(("config_snapshot_input", "config_snapshot_input", dict(
        config_namespace=1, schema=1,
        snapshot_hex=cf["old_snapshot_hex"]),
        SNAPSHOT_DOMAIN + u16(1) + u16(1) + bytes.fromhex(cf["old_snapshot_hex"])))

    for name, codec, fields, encoded in valid:
        record = {"format": fmt, "name": name, "codec": codec, "expect": "ok"}
        record.update(fields)
        record["encoded_hex"] = encoded.hex()
        emit("valid", name, record)

    def bad(name, codec, encoded, note):
        emit("invalid", name, {
            "format": fmt, "name": name, "codec": codec, "expect": "error",
            "note": note, "encoded_hex": encoded.hex()})

    tag = discover_body_bytes[8:]
    bad("discover_v2_bad_version", "scope_discover",
        u8(1) + discover_body_bytes[1:], "legacy/unknown body version")
    bad("discover_v2_bad_scheme", "scope_discover",
        discover_body_bytes[:2] + u8(2) + discover_body_bytes[3:],
        "unknown auth scheme")
    bad("discover_v2_bad_flags", "scope_discover",
        discover_body_bytes[:3] + u8(1) + discover_body_bytes[4:],
        "flags byte is reserved")
    bad("discover_v2_bad_class", "scope_discover",
        discover_body(3, 7, tag), "unknown scope class")
    bad("discover_v2_wrong_size", "scope_discover",
        discover_body_bytes[:-1], "23 bytes is not the v2 body")
    bad("discover_v2_legacy_empty", "scope_discover", b"",
        "legacy empty discover body must not decode as v2")
    bad("offer_v2_bad_version", "scope_offer",
        u8(1) + offer_body_bytes[1:], "legacy/unknown body version")
    bad("offer_v2_nonzero_reserved", "scope_offer",
        offer_body_bytes[:2] + u16(1) + offer_body_bytes[4:],
        "reserved u16 must be zero")
    bad("offer_v2_nonzero_flags", "scope_offer",
        offer_body_bytes[:38] + u16(1) + offer_body_bytes[40:],
        "flags u16 must be zero")
    bad("offer_v2_zero_nonce", "scope_offer",
        offer_body(0, b"\xa5" * 16, bytes(16), 1, 7, offer_body_bytes[44:]),
        "responder nonce must be nonzero")
    bad("offer_v2_legacy_v1", "scope_offer",
        u8(1) + bytes(35), "legacy 36B v1 offer body must not decode as v2")

    bad("service_query_bad_version", "service_query",
        u8(2) + service_query(2, nonce, digest32)[1:],
        "unsupported payload version")
    bad("service_query_bad_scope", "service_query",
        service_preamble(1, 0) + nonce + digest32, "unknown scope")
    bad("service_query_scope1_digest_nonzero", "service_query",
        service_query(1, nonce, digest32),
        "scope 1 requires an all-zero host digest")
    bad("service_query_scope2_digest_zero", "service_query",
        service_query(2, nonce, bytes(32)),
        "scope 2 forbids the any-host zero digest")
    bad("service_query_zero_nonce", "service_query",
        service_query(2, bytes(16), digest32), "nonce must be nonzero")
    bad("service_descriptor_zero_token", "service_descriptor",
        service_descriptor(2, nonce, bytes(16), 9, digest32, 3, 96, 15000),
        "token must be nonzero")
    bad("service_descriptor_max_payload_over", "service_descriptor",
        service_descriptor(2, nonce, token, 9, digest32, 3, 97, 15000),
        "max_payload exceeds the 96-byte registry bound")
    for row in ex["invalid_gateway"]:
        note = {
            "oversize97": "payload exceeds 96 bytes",
            "nonzero_flags": "flags byte must be zero",
            "truncated": "payload_len disagrees with bytes present",
            "unknown_scope": "unknown scope",
        }[row["id"]]
        bad(f"service_submit_{row['id']}", "service_submit",
            bytes.fromhex(row["encoded_hex"]), note)
    bad("service_submit_zero_token", "service_submit",
        service_submit(2, bytes(16), 9, b"x"), "token must be nonzero")
    bad("service_submit_zero_boot", "service_submit",
        service_submit(2, token, 0, b"x"), "gateway boot must be nonzero")
    bad("service_submit_reserved_set", "service_submit",
        service_submit(2, token, 9, b"x", reserved=1),
        "reserved u16 must be zero")
    bad("service_outcome_receipt_nonzero_reason", "service_outcome",
        service_outcome(4, 2, token, 9, 0x22, 7, 99, digest32, 4),
        "Receipt carries reason 0 only")
    bad("service_outcome_unknown_reason", "service_outcome",
        service_outcome(6, 2, token, 9, 0x22, 7, 99, digest32, 9),
        "reject reason 9 is unassigned")
    bad("service_outcome_zero_origin", "service_outcome",
        service_outcome(6, 2, token, 9, 0, 7, 99, digest32, 4),
        "referenced origin must be nonzero")
    bad("service_outcome_bad_subtype", "service_outcome",
        service_outcome(7, 2, token, 9, 0x22, 7, 99, digest32, 0),
        "subtype 7 is not an outcome subtype")

    bad("control_cq_reserved", "control_challenge_query",
        control_cq(1, 1, nonce, reserved=1), "reserved u16 must be zero")
    bad("control_cq_zero_nonce", "control_challenge_query",
        control_cq(1, 1, bytes(16)), "client nonce must be nonzero")
    bad("control_cq_bad_namespace", "control_challenge_query",
        control_cq(2, 1, nonce), "namespace 2 is unallocated")
    bad("control_cq_namespace_max", "control_challenge_query",
        control_cq(0xFFFF, 1, nonce), "0xffff is outside the app range")
    bad("control_challenge_zero_nonce", "control_challenge",
        control_challenge(1, 1, nonce, 9, bytes(16), 7, digest32, 30000),
        "challenge nonce must be nonzero")
    bad("control_challenge_zero_boot", "control_challenge",
        control_challenge(1, 1, nonce, 0, opid, 7, digest32, 30000),
        "target boot must be nonzero")
    bad("control_status_bad_phase", "control_status",
        control_status(1, opid, 8, 8, 9, 0, digest32),
        "phase 9 is unassigned")
    bad("control_status_bad_reason", "control_status",
        control_status(1, opid, 8, 8, 6, 16, digest32),
        "reason 16 exceeds the config table")
    bad("control_status_zero_opid", "control_status",
        control_status(1, bytes(16), 8, 8, 6, 0, digest32),
        "operation id must be nonzero")
    bad("control_status_reserved", "control_status",
        control_status(1, opid, 8, 8, 6, 0, digest32, reserved=1),
        "reserved byte must be zero")

    good_patch = tlv(1, 2, b"\x01") + tlv(3, 1, b"\x00")
    base = dict(ns=1, schema=1, field_count=2, network=1, target=0x30,
                authority=0x10, auth_gen=2, auth_seq=13, opid=opid,
                expected=7, nxt=8, base_hash=digest32,
                next_hash=bytes(range(32, 64)), target_boot=9,
                challenge_nonce=opid, apply_ms=5000)
    bad("config_bad_magic", "config_command",
        rcc1(magic=b"RCC2", patch=good_patch, **base), "bad magic")
    bad("config_bad_version", "config_command",
        rcc1(version=2, patch=good_patch, **base), "unknown RCC version")
    bad("config_bad_flags", "config_command",
        rcc1(flags=1, patch=good_patch, **base), "flags must be zero")
    bad("config_reserved_nonzero", "config_command",
        rcc1(reserved=1, patch=good_patch, **base), "reserved must be zero")
    bad("config_revision_mismatch", "config_command",
        rcc1(patch=good_patch, **{**base, "nxt": 9}),
        "next_revision must equal expected + 1")
    bad("config_revision_overflow", "config_command",
        rcc1(patch=good_patch,
             **{**base, "expected": 0xFFFFFFFFFFFFFFFF, "nxt": 0}),
        "revision overflow")
    bad("config_field_count_zero", "config_command",
        rcc1(patch=b"", **{**base, "field_count": 0}),
        "a no-op patch is never issued on the wire")
    bad("config_field_count_over", "config_command",
        rcc1(patch=tlv(1, 2, b"\x01") * 17, **{**base, "field_count": 17}),
        "field_count exceeds 16")
    bad("config_field_count_mismatch", "config_command",
        rcc1(patch=good_patch, **{**base, "field_count": 3}),
        "field_count disagrees with the TLV fields present")
    bad("config_patch_len_mismatch", "config_command",
        rcc1(patch=good_patch, patch_len=99, **base),
        "patch_len disagrees with bytes present")
    bad("config_oversize_patch", "config_command",
        rcc1(patch=tlv(1, 4, bytes(505)) + b"\x00" * 4,
             **{**base, "field_count": 1}), "patch exceeds 512 bytes")
    bad("config_tlv_bad_type", "config_command",
        rcc1(patch=u16(1) + u8(5) + u16(1) + b"\x00",
             **{**base, "field_count": 1}), "unknown TLV type")
    bad("config_tlv_dup", "config_command",
        rcc1(patch=tlv(1, 2, b"\x01") + tlv(1, 2, b"\x02"), **base),
        "duplicate field id")
    bad("config_tlv_out_of_order", "config_command",
        rcc1(patch=tlv(5, 2, b"\x01") + tlv(3, 2, b"\x02"), **base),
        "field ids must be strictly ascending")
    bad("config_tlv_value_oversize", "config_command",
        rcc1(patch=u16(1) + u8(4) + u16(97) + bytes(97),
             **{**base, "field_count": 1}), "field value exceeds 96 bytes")
    bad("config_tlv_numeric_wrong_len", "config_command",
        rcc1(patch=u16(1) + u8(2) + u16(2) + b"\x01\x02",
             **{**base, "field_count": 1}), "u8 field must declare length 1")
    bad("config_tlv_bool_bad_value", "config_command",
        rcc1(patch=u16(1) + u8(1) + u16(1) + b"\x02",
             **{**base, "field_count": 1}), "bool value must be 0 or 1")
    bad("config_tlv_truncated", "config_command",
        rcc1(patch=u16(1) + u8(4) + u16(9) + b"ab",
             **{**base, "field_count": 1}),
        "TLV value shorter than its declared length")
    bad("config_zero_opid", "config_command",
        rcc1(patch=good_patch, **{**base, "opid": bytes(16)}),
        "operation id must be nonzero")
    bad("config_zero_network", "config_command",
        rcc1(patch=good_patch, **{**base, "network": 0}),
        "network must be nonzero")
    bad("config_bad_namespace", "config_command",
        rcc1(patch=good_patch, **{**base, "ns": 0x7000}),
        "namespace outside the registered ranges")
    bad("config_zero_challenge", "config_command",
        rcc1(patch=good_patch, **{**base, "challenge_nonce": bytes(16)}),
        "challenge nonce must be nonzero")
    # Zero node-id fields: 0 is the reserved invalid id, never a peer.
    bad("config_zero_target", "config_command",
        rcc1(patch=good_patch, **{**base, "target": 0}),
        "target 0 is the invalid node id")
    bad("config_zero_authority", "config_command",
        rcc1(patch=good_patch, **{**base, "authority": 0}),
        "authority 0 is the invalid node id")
    # Trailing bytes: a decoder consumes exactly its frame — leftover bytes
    # are a framing violation, never ignorable padding.
    bad("config_trailing_byte", "config_command",
        rcc1(patch=good_patch + b"\x00", **base),
        "one byte trails the declared TLV region")
    bad("service_submit_trailing", "service_submit",
        service_submit(2, token, 9, b"xy", declared=1),
        "payload_len is one byte short of the bytes present")
    bad("service_query_trailing", "service_query",
        service_query(2, nonce, digest32) + b"\x00",
        "fixed-size query with a trailing byte")
    bad("control_status_trailing", "control_status",
        control_status(1, opid, 8, 8, 6, 0, digest32) + b"\x00",
        "fixed-size status with a trailing byte")
    bad("discover_v2_trailing", "scope_discover",
        discover_body_bytes + b"\x00",
        "25 bytes is not the v2 body either")

    print(f"wrote {len(list((OUT / 'valid').glob('*.json')))} valid and "
          f"{len(list((OUT / 'invalid').glob('*.json')))} invalid vectors to {OUT}")


if __name__ == "__main__":
    main()
