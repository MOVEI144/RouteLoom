#!/usr/bin/env python3
"""Regenerate protocol/autonomy-golden/*.json for the autonomy payload codecs.

The layouts mirror components/routeloom/src/autonomy_wire.cpp and
host/routeloom-wire/src/autonomy.rs. All integers are big-endian; reserved
bytes are 0. These vectors pin byte layouts only — they carry no crypto
claims (suite pending, G-SEC).
"""
from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "autonomy-golden"

PAYLOAD_VERSION = 1
RLD1_MAGIC = b"RLD1"
RLD1_VERSION = 1
RLD1_HEADER = 44
RLD1_MAX_BODY = 116
RLD1_MAX_TOTAL = 160

# FrameType ids used by the vectors.
DISCOVER, OFFER, BOOTSTRAP_AUTH, MEMBERSHIP_RESULT = 1, 2, 3, 4
BOOTSTRAP_CHUNK, BOOTSTRAP_REPLY, MEMBERSHIP_QUERY = 5, 6, 7
DATA, BUSY, ROUTE_UPDATE = 16, 20, 32

def u8(v): return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)


def busy(subtype, reason, ref_type, ref_origin, ref_session, ref_seq, ref_round,
         binding, feedback, retry_after, pressure):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + u8(reason) + u8(ref_type) +
            u64(ref_origin) + u32(ref_session) + u64(ref_seq) + u8(ref_round) +
            u32(binding) + u32(feedback) + u32(retry_after) + u8(pressure))


def time_sync(subtype, source, sequence, reference_ms, uncertainty_ms):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + u64(source) + u32(sequence) +
            u64(reference_ms) + u32(uncertainty_ms))


def channel_notice(subtype, subject, epoch, starts_in, duration, reason,
                   cut_id=0):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + u64(subject) + u32(epoch) +
            u32(starts_in) + u32(duration) + u8(reason) + u16(cut_id))


def neighbor_probe(subtype, binding, probe_seq, sent_ms, lease_ms):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + u32(binding) + u32(probe_seq) +
            u64(sent_ms) + u32(lease_ms))


def neighbor_result(subtype, binding, probe_seq, result, pressure,
                    queue_ms, airtime_us, lease_ms):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + u32(binding) + u32(probe_seq) +
            u8(result) + u8(pressure) + u32(queue_ms) + u32(airtime_us) +
            u32(lease_ms))


def control_object(subtype, kind, flags, total_len, obj_hash):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + u8(kind) + u8(flags) +
            u16(total_len) + obj_hash)


def object_chunk(subtype, obj_hash, offset, data):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + obj_hash + u16(offset) +
            u16(len(data)) + data)


def object_ack(subtype, obj_hash, received_len, status):
    return (u8(PAYLOAD_VERSION) + u8(subtype) + obj_hash + u16(received_len) +
            u8(status))


def bootstrap_auth(version, phase, step, reserved, body):
    return u8(version) + u8(phase) + u8(step) + u8(reserved) + body


def rld1(kind, flags, network_hint, claimed_node, nonce, capability, body,
         version=RLD1_VERSION, header_len=RLD1_HEADER, total_len=None):
    if total_len is None:
        total_len = RLD1_HEADER + len(body)
    return (RLD1_MAGIC + u8(version) + u8(kind) + u16(header_len) +
            u16(total_len) + u16(flags) + u32(network_hint) + u64(claimed_node) +
            nonce + u32(capability) + body)


def emit(folder, name, record):
    path = OUT / folder / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def main():
    # Only the generated folders are wiped: top-level files such as
    # README.md are checked-in documentation, not generator output.
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)

    fmt = "routeloom-autonomy-v1-golden"
    obj_hash = bytes(range(32))          # 00..1f deterministic
    nonce = bytes(range(16))             # 00..0f deterministic
    auth_body = bootstrap_auth(PAYLOAD_VERSION, 1, 0, 0, b"prove-body")

    valid = [
        ("busy_reject", "busy", dict(
            subtype=1, reason=1, referenced_type=DATA, referenced_origin=0x0102030405060708,
            referenced_session=7, referenced_sequence=0x1122334455667788,
            referenced_round=2, binding_generation=9, feedback_sequence=11,
            retry_after_ms=250, pressure=128),
         busy(1, 1, DATA, 0x0102030405060708, 7, 0x1122334455667788, 2, 9, 11, 250, 128)),
        ("busy_pressure_hint", "busy", dict(
            subtype=2, reason=5, referenced_type=ROUTE_UPDATE, referenced_origin=5,
            referenced_session=3, referenced_sequence=99, referenced_round=0,
            binding_generation=4, feedback_sequence=77, retry_after_ms=1000,
            pressure=255),
         busy(2, 5, ROUTE_UPDATE, 5, 3, 99, 0, 4, 77, 1000, 255)),
        ("time_sync_sample", "time_sync", dict(
            subtype=1, source=0xA1A2A3A4A5A6A7A8, sequence=42,
            reference_ms=3600000, uncertainty_ms=12),
         time_sync(1, 0xA1A2A3A4A5A6A7A8, 42, 3600000, 12)),
        ("channel_notice_absence", "channel_notice", dict(
            subtype=1, subject=0x0B0C0D0E0F101112, channel_epoch=3,
            starts_in_ms=150, duration_ms=200, reason=1,
            protected_cut_id=7),
         channel_notice(1, 0x0B0C0D0E0F101112, 3, 150, 200, 1, 7)),
        ("neighbor_probe", "neighbor_probe", dict(
            subtype=1, binding_generation=2, probe_sequence=1001,
            sent_ms=123456789, requested_lease_ms=30000),
         neighbor_probe(1, 2, 1001, 123456789, 30000)),
        ("neighbor_result_reachable", "neighbor_result", dict(
            subtype=1, binding_generation=2, probe_sequence=1001, result=1,
            pressure=32, queue_delay_ms=18, est_airtime_us=9312,
            lease_granted_ms=30000),
         neighbor_result(1, 2, 1001, 1, 32, 18, 9312, 30000)),
        ("control_object_channel_plan", "control_object", dict(
            subtype=1, kind=1, total_len=512, object_hash_hex=obj_hash.hex()),
         control_object(1, 1, 0, 512, obj_hash)),
        ("object_chunk_first", "object_chunk", dict(
            subtype=1, object_hash_hex=obj_hash.hex(), offset=0,
            data_hex=bytes(range(32)).hex()),
         object_chunk(1, obj_hash, 0, bytes(range(32)))),
        ("object_chunk_offset", "object_chunk", dict(
            subtype=1, object_hash_hex=obj_hash.hex(), offset=256,
            data_hex=(b"\xaa" * 16).hex()),
         object_chunk(1, obj_hash, 256, b"\xaa" * 16)),
        ("object_ack_complete", "object_ack", dict(
            subtype=1, object_hash_hex=obj_hash.hex(), received_len=512,
            status=0),
         object_ack(1, obj_hash, 512, 0)),
        ("bootstrap_auth_prove", "bootstrap_auth", dict(
            phase=1, step_index=0, body_hex=b"prove-body".hex()),
         auth_body),
        ("rld1_discover", "rld1", dict(
            kind=DISCOVER, flags=0, network_hint=0xC0FFEE01,
            claimed_node=0x0102030405060708, nonce_hex=nonce.hex(),
            capability_bits=0x00000003, body_hex=b"disc-hint".hex()),
         rld1(DISCOVER, 0, 0xC0FFEE01, 0x0102030405060708, nonce, 3, b"disc-hint")),
        ("rld1_offer_cookie", "rld1", dict(
            kind=OFFER, flags=0, network_hint=0xC0FFEE01,
            claimed_node=0x1112131415161718, nonce_hex=nonce.hex(),
            capability_bits=0x00000003, body_hex=(b"cookie32-bytes-padding-to-32bytes!!").hex()),
         rld1(OFFER, 0, 0xC0FFEE01, 0x1112131415161718, nonce, 3,
              b"cookie32-bytes-padding-to-32bytes!!")),
        ("rld1_auth_prove", "rld1", dict(
            kind=BOOTSTRAP_AUTH, flags=0, network_hint=0xC0FFEE01,
            claimed_node=0x0102030405060708, nonce_hex=nonce.hex(),
            capability_bits=0x00000003, body_hex=auth_body.hex()),
         rld1(BOOTSTRAP_AUTH, 0, 0xC0FFEE01, 0x0102030405060708, nonce, 3, auth_body)),
        ("rld1_bootstrap_chunk", "rld1", dict(
            kind=BOOTSTRAP_CHUNK, flags=0, network_hint=0xC0FFEE01,
            claimed_node=0x0102030405060708, nonce_hex=nonce.hex(),
            capability_bits=0x00000003, body_hex=(b"\x01" * 40).hex()),
         rld1(BOOTSTRAP_CHUNK, 0, 0xC0FFEE01, 0x0102030405060708, nonce, 3, b"\x01" * 40)),
        ("rld1_bootstrap_reply", "rld1", dict(
            kind=BOOTSTRAP_REPLY, flags=0, network_hint=0xC0FFEE01,
            claimed_node=0x1112131415161718, nonce_hex=nonce.hex(),
            capability_bits=0x00000003, body_hex=b"ack".hex()),
         rld1(BOOTSTRAP_REPLY, 0, 0xC0FFEE01, 0x1112131415161718, nonce, 3, b"ack")),
        ("rld1_max_body", "rld1", dict(
            kind=DISCOVER, flags=0, network_hint=0xFFFFFFFF,
            claimed_node=0xFFFFFFFFFFFFFFFF, nonce_hex=nonce.hex(),
            capability_bits=0xFFFFFFFF, body_hex=(b"\x5a" * RLD1_MAX_BODY).hex()),
         rld1(DISCOVER, 0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, nonce, 0xFFFFFFFF,
              b"\x5a" * RLD1_MAX_BODY)),
    ]
    for name, codec, fields, encoded in valid:
        record = {"format": fmt, "name": name, "codec": codec, "expect": "ok"}
        record.update(fields)
        record["encoded_hex"] = encoded.hex() if isinstance(encoded, bytes) else encoded.hex()
        emit("valid", name, record)

    # Invalid vectors: every one must fail decode (and, for the Wire-magic
    # case, must not even probe as RLD1).
    def bad(name, codec, encoded, note, probe=None):
        record = {"format": fmt, "name": name, "codec": codec,
                  "expect": "error", "note": note,
                  "encoded_hex": encoded.hex()}
        if probe is not None:
            record["probe"] = "true" if probe else "false"
        emit("invalid", name, record)

    # A genuine Wire v1 frame prefix ("RL" + version) is never RLD1.
    bad("rld1_wire_frame_not_rld1", "rld1",
        b"RL" + u8(1) + u8(0) + b"\x10" + b"\x00" * 60,
        "Wire v1 magic must not classify or decode as RLD1", probe=False)
    bad("rld1_kind_membership_result", "rld1",
        rld1(MEMBERSHIP_RESULT, 0, 1, 2, nonce, 0, b"x"),
        "kind 4 is forbidden on the RLD1 carrier")
    bad("rld1_kind_membership_query", "rld1",
        rld1(MEMBERSHIP_QUERY, 0, 1, 2, nonce, 0, b"x"),
        "kind 7 is forbidden on the RLD1 carrier")
    bad("rld1_kind_data", "rld1",
        rld1(DATA, 0, 1, 2, nonce, 0, b"x"),
        "kind 16 (DATA) is forbidden on the RLD1 carrier")
    bad("rld1_length_mismatch", "rld1",
        rld1(DISCOVER, 0, 1, 2, nonce, 0, b"abc", total_len=RLD1_HEADER + 99),
        "total_len disagrees with the actual size")
    bad("rld1_truncated_header", "rld1",
        rld1(DISCOVER, 0, 1, 2, nonce, 0, b"")[:30],
        "shorter than the 44-byte header")
    bad("rld1_oversize", "rld1",
        rld1(DISCOVER, 0, 1, 2, nonce, 0, b"\x00" * 200),
        "exceeds the 160-byte total limit")
    bad("rld1_flags_reserved_set", "rld1",
        rld1(DISCOVER, 0x0001, 1, 2, nonce, 0, b"x"),
        "v1 flags are reserved and must be zero")
    bad("rld1_bad_version", "rld1",
        rld1(DISCOVER, 0, 1, 2, nonce, 0, b"x", version=2),
        "unsupported RLD1 version")
    bad("rld1_bad_header_len", "rld1",
        rld1(DISCOVER, 0, 1, 2, nonce, 0, b"x", header_len=45),
        "header_len must be exactly 44")
    bad("busy_bad_version", "busy",
        u8(2) + busy(1, 1, DATA, 5, 7, 9, 0, 1, 2, 20, 10)[1:],
        "unsupported payload version")
    bad("busy_bad_subtype", "busy",
        busy(9, 1, DATA, 5, 7, 9, 0, 1, 2, 20, 10),
        "unknown Busy subtype")
    bad("busy_bad_reason", "busy",
        busy(1, 99, DATA, 5, 7, 9, 0, 1, 2, 20, 10),
        "unknown Busy reason")
    bad("busy_wrong_size", "busy",
        busy(1, 1, DATA, 5, 7, 9, 0, 1, 2, 20, 10)[:-1],
        "37-byte Busy payload is a length mismatch")
    bad("object_chunk_length_mismatch", "object_chunk",
        u8(PAYLOAD_VERSION) + u8(1) + obj_hash + u16(0) + u16(5) + b"ab",
        "declared chunk length disagrees with bytes present")
    bad("object_chunk_past_object_limit", "object_chunk",
        u8(PAYLOAD_VERSION) + u8(1) + obj_hash + u16(2040) + u16(9) + b"\x00" * 9,
        "offset+length exceeds the 2048-byte object limit")
    bad("channel_notice_reason_invalid", "channel_notice",
        channel_notice(1, 5, 3, 150, 200, 0x09),
        "absence reason above the valid enum range")
    bad("bootstrap_auth_bad_phase", "bootstrap_auth",
        bootstrap_auth(PAYLOAD_VERSION, 7, 0, 0, b"x"),
        "auth phase 7 is not a logical phase")
    bad("control_object_oversize", "control_object",
        control_object(1, 1, 0, 3000, obj_hash),
        "total_len exceeds the 2048-byte object limit")

    print(f"wrote {len(list((OUT / 'valid').glob('*.json')))} valid and "
          f"{len(list((OUT / 'invalid').glob('*.json')))} invalid vectors to {OUT}")


if __name__ == "__main__":
    main()
