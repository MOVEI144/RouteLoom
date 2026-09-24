#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/authority/ (G-SEC P5 PR1).

Independent reference for the authority-channel wire of
docs/design/sdk-v1/03-key-hierarchy.md section 5.3 and the G-SEC P5 design
section 3: the AuthorityEnvelope bodies (JoinConfirm / GroupKeyUpdate /
GroupKeyActivate / GroupKeyPull), their AES-GCM-128 sealings, the GK-id
derivation, the USB HostOps 0x64-0x67 fragment encodings and the mesh
AuthorityCarrier head. Written from the design text; it shares no code with
the C++ (components/routeloom/src/sdkv1_authority.cpp, usb_host_ops.cpp) or
Rust (host/routeloom-keysched/src/authority.rs,
host/routeloom-protocol/src/authority.rs and host_ops.rs) implementations,
which must both reproduce every byte below.

The envelope keys come from the purpose-4 RLRES1 transcript. The transcript
inputs are re-declared here and re-derived with the Python standard library
only (hmac/hashlib/struct, same construction as
tools/gen_sdkv1_derivation_vectors.py but no shared code); the result is
asserted byte-for-byte against
protocol/sdkv1-golden/derivations/valid/rlres1_authority.json so the two
suites cannot drift apart. AES-GCM sealings use the `cryptography` package
(pinned for CI, see .github/workflows/sdk.yml); every sealed envelope is
opened again in-process to catch generator bugs.

Conventions (frozen by the P5 design):
  * integers are big-endian, reserved/flags bytes are zero, unknown
    version/op/type or trailing bytes are refused;
  * body head (16 B): body_version:u8=1 | op:u8 | flags:u16=0 |
    assignment_generation:u32!=0 | request_id:u64!=0;
  * envelope (28..2048 B): ver:u8=1 | type:u8=1..8 | ctx_id:u32!=0 |
    counter:u48 | ciphertext | tag:16; the 12-byte header is the AAD and
    nonce = base_iv XOR (zero6 || counter:u48);
  * GK-id = SHA256("RouteLoom/v1/gk-id" || 0x00 || network:u64 ||
    epoch:u32 || GK:32).

The fixed inputs below are TEST VALUES (not secrets of any deployment).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.stderr.write(
        "gen_sdkv1_authority_vectors.py needs the 'cryptography' package "
        "(CI installs the pinned version; see .github/workflows/sdk.yml).\n"
    )
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden" / "authority"
DERIVATIONS = ROOT / "protocol" / "sdkv1-golden" / "derivations" / "valid"
FORMAT = "routeloom-sdkv1-authority-golden-v1"

# --- frozen labels -----------------------------------------------------------
L_RID = b"RouteLoom/v1/rid"
L_AUTH = b"RouteLoom/v1/resume-auth"
L_BIND = b"RouteLoom/v1/resume-binding"
L_R1 = b"RouteLoom/v1/R1"
L_R2 = b"RouteLoom/v1/R2"
L_R3 = b"RouteLoom/v1/R3"
L_CONF = b"RouteLoom/v1/resume-confirm"
L_KEY = b"RouteLoom/v1/resume-key"
L_GK_ID = b"RouteLoom/v1/gk-id"

PURPOSE_AUTHORITY = 4
DIR_IR, DIR_RI = 1, 2  # initiator->responder, responder->initiator

TYPE_JOIN_CONFIRM, TYPE_UPDATE, TYPE_ACTIVATE, TYPE_PULL = 1, 2, 3, 4

MAX_COUNTER = (1 << 48) - 1


def info(label: bytes, *fields: bytes) -> bytes:
    return label + b"\x00" + b"".join(fields)


def h32(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, data: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + data + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def u48(v: int) -> bytes:
    return v.to_bytes(6, "big")


# --- purpose-4 transcript (re-derived, then checked against derivations) ----

def pattern(seed: int, n: int) -> bytes:
    """Deterministic, obviously-synthetic test bytes (same values as the
    derivations generator's helper, re-declared so this file stays
    independent)."""
    return bytes((seed + 17 * i) & 0xFF for i in range(n))


# Test inputs shared with derivations' rlres1_authority.json.
DAMS = pattern(0x03, 32)
NETWORK = (7 << 32) | 0x0A0B0C0D
NODE_I = 0x101
SITE_ID = 0x5100000000000042
NONCE_I = pattern(0x23, 16)
NONCE_R = pattern(0x43, 16)
CID_I, CID_R = 0x55555555, 0x66666666
EPOCHS_I = (7, 2, 10)  # site, rs, gk
EPOCHS_R = (7, 4, 12)


def epochs_bytes(e: tuple[int, int, int]) -> bytes:
    return u32(e[0]) + u32(e[1]) + u32(e[2])


def r1_bytes(rid: bytes, epochs: tuple[int, int, int], cid: int, mac: bytes) -> bytes:
    return (
        u8(PURPOSE_AUTHORITY)
        + b"\x00\x00\x00"
        + rid
        + NONCE_I
        + u32(cid)
        + epochs_bytes(epochs)
        + mac
    )


def r2_ok_bytes(epochs: tuple[int, int, int], cid: int, mac: bytes) -> bytes:
    return b"\x00\x00\x00\x00" + NONCE_R + u32(cid) + epochs_bytes(epochs) + mac


def transcript() -> dict:
    rid = h32(DAMS, info(L_RID, u8(PURPOSE_AUTHORITY)))[:8]
    k_auth = hkdf_expand(
        hkdf_extract(L_AUTH, DAMS),
        info(L_AUTH, u8(PURPOSE_AUTHORITY), u64(NETWORK), u64(NODE_I), u64(SITE_ID)),
        32,
    )
    binding = hashlib.sha256(
        info(L_BIND, u8(PURPOSE_AUTHORITY), u64(NODE_I), u64(SITE_ID))
    ).digest()
    mac_i = h32(k_auth, info(L_R1) + binding + r1_bytes(rid, EPOCHS_I, CID_I, b""))[:16]
    r1 = r1_bytes(rid, EPOCHS_I, CID_I, mac_i)
    r2_body = r2_ok_bytes(EPOCHS_R, CID_R, b"")
    mac_r = h32(k_auth, info(L_R2) + binding + r1 + r2_body)[:16]
    r2 = r2_ok_bytes(EPOCHS_R, CID_R, mac_r)
    th = hashlib.sha256(r1 + r2).digest()
    prk = hkdf_extract(NONCE_I + NONCE_R, DAMS)
    k_conf = hkdf_expand(prk, info(L_CONF, th), 32)

    def traffic(direction: int) -> tuple[bytes, bytes]:
        okm = hkdf_expand(
            prk,
            info(
                L_KEY,
                u8(PURPOSE_AUTHORITY) + u8(direction),
                u64(NETWORK),
                u64(NODE_I),
                u64(SITE_ID),
                u32(CID_I),
                u32(CID_R),
                th,
            ),
            28,
        )
        return okm[:16], okm[16:]

    key_ir, iv_ir = traffic(DIR_IR)
    key_ri, iv_ri = traffic(DIR_RI)
    mac_i3 = h32(k_conf, info(L_R3) + th)[:16]
    return {
        "rid": rid,
        "k_auth": k_auth,
        "binding": binding,
        "r1": r1,
        "r2": r2,
        "r3": mac_i3,
        "th": th,
        "prk": prk,
        "k_conf": k_conf,
        "key_ir": key_ir,
        "iv_ir": iv_ir,
        "key_ri": key_ri,
        "iv_ri": iv_ri,
    }


def check_transcript_against_derivations(t: dict) -> None:
    ref = json.loads((DERIVATIONS / "rlres1_authority.json").read_text())
    assert ref["rms_hex"] == DAMS.hex(), "DAMS test input drifted"
    assert ref["rid_hex"] == t["rid"].hex()
    assert ref["k_auth_hex"] == t["k_auth"].hex()
    assert ref["binding_hex"] == t["binding"].hex()
    assert ref["r1_hex"] == t["r1"].hex()
    assert ref["r2_hex"] == t["r2"].hex()
    assert ref["r3_hex"] == t["r3"].hex()
    assert ref["th_hex"] == t["th"].hex()
    assert ref["prk_hex"] == t["prk"].hex()
    assert ref["k_conf_hex"] == t["k_conf"].hex()
    assert ref["key_ir_hex"] == t["key_ir"].hex()
    assert ref["iv_ir_hex"] == t["iv_ir"].hex()
    assert ref["key_ri_hex"] == t["key_ri"].hex()
    assert ref["iv_ri_hex"] == t["iv_ri"].hex()


# --- bodies ------------------------------------------------------------------

ASSIGNMENT_GENERATION = 9
REQUEST_ID = 0x0102030405060708


def head(op: int, generation: int = ASSIGNMENT_GENERATION, request: int = REQUEST_ID) -> bytes:
    return u8(1) + u8(op) + u16(0) + u32(generation) + u64(request)


CERT_HASH = hashlib.sha256(b"authority-test-member-cert").digest()
GK = bytes(0xA0 + i for i in range(32))


def gk_id(network: int, epoch: int, gk: bytes) -> bytes:
    return hashlib.sha256(info(L_GK_ID, u64(network), u32(epoch), gk)).digest()


def bodies(gkid: bytes) -> list:
    """(name, type, op, plaintext, decoded fields)."""
    return [
        (
            "join_confirm_device",
            TYPE_JOIN_CONFIRM,
            1,
            head(1) + CERT_HASH + u32(5) + u32(10) + u32(11),
            {"cert_hash_hex": CERT_HASH.hex(), "boot": 5, "current": 10, "next": 11},
        ),
        (
            "join_confirm_authority",
            TYPE_JOIN_CONFIRM,
            2,
            head(2) + u32(9) + u32(10),
            {"confirmed_generation": 9, "authority_active": 10},
        ),
        (
            "group_key_update",
            TYPE_UPDATE,
            1,
            head(1) + u32(11) + u8(1) + u8(0) + u16(60) + GK,
            {"g": 11, "cause": 1, "overlap_s": 60, "gk_hex": GK.hex()},
        ),
        (
            "group_key_update_ack",
            TYPE_UPDATE,
            2,
            head(2) + u32(11) + gkid + u8(0) + u8(2) + u16(0),
            {"g": 11, "gk_id_hex": gkid.hex(), "result": 0, "stored_state": 2},
        ),
        (
            "group_key_activate",
            TYPE_ACTIVATE,
            1,
            head(1) + u32(11) + gkid + u8(1) + u8(0) + u16(60),
            {"g": 11, "gk_id_hex": gkid.hex(), "cause": 1, "overlap_s": 60},
        ),
        (
            "group_key_activate_ack",
            TYPE_ACTIVATE,
            2,
            head(2) + u32(11) + gkid + u8(0) + u8(2) + u16(0),
            {"g": 11, "gk_id_hex": gkid.hex(), "result": 0, "stored_state": 2},
        ),
        (
            "group_key_pull",
            TYPE_PULL,
            1,
            head(1) + u32(10) + u32(0) + u8(2) + b"\x00\x00\x00",
            {"current": 10, "next": 0, "reason": 2},
        ),
    ]


# --- envelopes ---------------------------------------------------------------

# Plaintext direction: which traffic key seals it (D=device/initiator,
# A=authority/responder).
D_TO_A = {
    "join_confirm_device",
    "group_key_update_ack",
    "group_key_activate_ack",
    "group_key_pull",
}


def seal_envelope(
    env_type: int, ctx_id: int, counter: int, key: bytes, iv: bytes, plaintext: bytes
) -> bytes:
    header = u8(1) + u8(env_type) + u32(ctx_id) + u48(counter)
    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 6 + u48(counter)))
    sealed = AESGCM(key).encrypt(nonce, plaintext, header)
    # Round-trip in-process: a generator bug must fail here, not in a golden.
    assert AESGCM(key).decrypt(nonce, sealed, header) == plaintext
    return header + sealed


# --- USB 0x64-0x67 inner bodies -----------------------------------------------

SUB_UP, SUB_DOWN, SUB_SET, SUB_REPORT = 0x64, 0x65, 0x66, 0x67
FRAG_DATA_MAX = 960


def fragment(device: int, transfer: int, kind: int, hops: int, total: int, offset: int,
             data: bytes) -> bytes:
    assert len(data) <= FRAG_DATA_MAX
    return (
        u64(device)
        + u32(transfer)
        + u8(kind)
        + u8(hops)
        + u16(total)
        + u16(offset)
        + u16(len(data))
        + data
    )


def inner(sub: int, payload: bytes) -> bytes:
    return u8(1) + u8(sub) + u16(len(payload)) + payload


# --- mesh carrier head ---------------------------------------------------------

CARRIER_SUB = 5


def carrier_head(kind: int, exchange_id: int) -> bytes:
    return u8(1) + u8(CARRIER_SUB) + u8(kind) + u8(0) + u32(exchange_id)


# --- emission ------------------------------------------------------------------

def emit(name: str, subdir: str, obj: dict) -> None:
    obj = {"name": name, "format": FORMAT, **obj}
    path = OUT / subdir / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "valid").mkdir(parents=True)
    (OUT / "invalid").mkdir(parents=True)

    t = transcript()
    check_transcript_against_derivations(t)
    gkid = gk_id(NETWORK, 11, GK)

    # GK-id vectors.
    emit("gk_id_epoch11", "valid", {
        "codec": "gk_id", "expect": "ok", "network": NETWORK, "epoch": 11,
        "gk_hex": GK.hex(), "gk_id_hex": gkid.hex(),
    })
    other = gk_id(NETWORK, 1, bytes(32))
    emit("gk_id_epoch1_zero_key", "valid", {
        "codec": "gk_id", "expect": "ok", "network": NETWORK, "epoch": 1,
        "gk_hex": bytes(32).hex(), "gk_id_hex": other.hex(),
    })

    # Bodies and their sealed envelopes (counter 1; direction key as on wire).
    for name, env_type, op, plaintext, fields in bodies(gkid):
        emit(f"body_{name}", "valid", {
            "codec": "authority_body", "expect": "ok", "type": env_type, "op": op,
            "generation": ASSIGNMENT_GENERATION, "request_id": REQUEST_ID,
            "plaintext_hex": plaintext.hex(), **fields,
        })
        if name in D_TO_A:
            key, iv = t["key_ir"], t["iv_ir"]
            ctx = CID_R  # receiver (authority) chose it
            direction = "device_to_authority"
        else:
            key, iv = t["key_ri"], t["iv_ri"]
            ctx = CID_I  # receiver (device) chose it
            direction = "authority_to_device"
        envelope = seal_envelope(env_type, ctx, 1, key, iv, plaintext)
        emit(f"envelope_{name}", "valid", {
            "codec": "authority_envelope", "expect": "ok", "type": env_type,
            "direction": direction, "ctx_id": ctx, "counter": 1,
            "key_hex": key.hex(), "iv_hex": iv.hex(),
            "plaintext_hex": plaintext.hex(), "envelope_hex": envelope.hex(),
        })

    # Counter boundaries on the Pull envelope (device-to-authority key).
    pull = next(p for n, _, _, p, _ in bodies(gkid) if n == "group_key_pull")
    for counter in (0, (1 << 32) - 1, 1 << 32, MAX_COUNTER):
        envelope = seal_envelope(TYPE_PULL, CID_R, counter, t["key_ir"], t["iv_ir"], pull)
        emit(f"envelope_pull_counter_{counter}", "valid", {
            "codec": "authority_envelope", "expect": "ok", "type": TYPE_PULL,
            "direction": "device_to_authority", "ctx_id": CID_R, "counter": counter,
            "key_hex": t["key_ir"].hex(), "iv_hex": t["iv_ir"].hex(),
            "plaintext_hex": pull.hex(), "envelope_hex": envelope.hex(),
        })

    # A tampered envelope: same bytes with one ciphertext bit flipped under
    # the intact tag — open must fail, never emit plaintext.
    good = seal_envelope(TYPE_PULL, CID_R, 7, t["key_ir"], t["iv_ir"], pull)
    bad = bytearray(good)
    bad[20] ^= 0x01
    emit("envelope_pull_bad_tag", "invalid", {
        "codec": "authority_envelope", "expect": "error", "reason": "bad_tag",
        "note": "one ciphertext bit flipped under the intact tag",
        "key_hex": t["key_ir"].hex(), "iv_hex": t["iv_ir"].hex(),
        "envelope_hex": bytes(bad).hex(),
    })
    # Cross-direction key: sealed device-to-authority, opened with the
    # authority-to-device key of the same channel.
    emit("envelope_pull_wrong_direction", "invalid", {
        "codec": "authority_envelope", "expect": "error", "reason": "bad_tag",
        "note": "device-to-authority bytes opened with the authority-to-device key",
        "key_hex": t["key_ri"].hex(), "iv_hex": t["iv_ri"].hex(),
        "envelope_hex": good.hex(),
    })

    # Body negatives (all against the 56-byte Update shape unless noted).
    update = next(p for n, _, _, p, _ in bodies(gkid) if n == "group_key_update")
    negatives = [
        ("body_truncated", update[:-1], "truncated", "55 of 56 bytes"),
        ("body_surplus", update + b"\x00", "surplus", "57 of 56 bytes"),
        ("body_bad_version", b"\x02" + update[1:], "bad_version", "body_version 2"),
        ("body_bad_op", update[:1] + b"\x03" + update[2:], "bad_op",
         "op 3 is undefined"),
        ("body_flags_set", update[:2] + b"\x00\x01" + update[4:], "reserved_nonzero",
         "head flags bit set"),
        ("body_zero_generation", update[:4] + u32(0) + update[8:], "zero_generation",
         "assignment_generation 0"),
        ("body_zero_request", update[:8] + u64(0) + update[16:], "zero_request_id",
         "request_id 0"),
        ("body_update_bad_cause", update[:20] + b"\x09" + update[21:], "bad_cause",
         "cause 9 is undefined"),
        ("body_update_bad_overlap", update[:22] + u16(61) + update[24:], "bad_overlap",
         "overlap 61 s is not an allowed value"),
    ]
    ack = next(p for n, _, _, p, _ in bodies(gkid) if n == "group_key_update_ack")
    negatives += [
        ("body_ack_bad_result", ack[:52] + b"\x09" + ack[53:], "bad_result",
         "result 9 is undefined"),
        ("body_ack_bad_state", ack[:53] + b"\x07" + ack[54:], "bad_stored_state",
         "stored_state 7 is undefined"),
        ("body_ack_durable_none", ack[:52] + b"\x00\x00" + ack[54:],
         "bad_stored_state", "durable ACK requires a stored key state"),
    ]
    negatives += [
        ("body_pull_bad_reason", pull[:24] + b"\x09" + pull[25:], "bad_reason",
         "reason 9 is undefined"),
        ("body_pull_wrong_length", pull + b"\x00" * 28, "surplus",
         "Pull must be exactly 28 bytes"),
        ("body_update_removal_long_overlap",
         update[:20] + b"\x02" + update[21:22] + u16(60) + update[24:],
         "bad_overlap", "removal must pair cause 2 with overlap 10 s"),
    ]
    for name, encoded, reason, note in negatives:
        emit(name, "invalid", {
            "codec": "authority_body", "expect": "error", "reason": reason,
            "note": note, "encoded_hex": encoded.hex(),
        })

    # USB fragments: 960/961/1920/2048-byte objects over 0x64/0x65.
    device, transfer = 0x101, 0x00C0FFEE
    for total in (960, 961, 1920, 2048):
        payload = bytes((0x55 + i) & 0xFF for i in range(total))
        frags = [payload[i:i + FRAG_DATA_MAX] for i in range(0, total, FRAG_DATA_MAX)]
        for index, data in enumerate(frags):
            offset = index * FRAG_DATA_MAX
            for sub in (SUB_UP, SUB_DOWN):
                hops = 3 if sub == SUB_UP else 0
                tag = "up" if sub == SUB_UP else "down"
                emit(f"fragment_{tag}_{total}_part{index}", "valid", {
                    "codec": "authority_fragment", "expect": "ok", "sub": sub,
                    "device": device, "transfer_id": transfer, "kind": 4,
                    "hops": hops, "total": total, "offset": offset,
                    "length": len(data),
                    "inner_hex": inner(sub, fragment(device, transfer, 4, hops,
                                                     total, offset, data)).hex(),
                })
    # Single R1 fragment (kind 1, 60 B) and a Wake fragment (kind 5, 8 B).
    r1frag = fragment(device, transfer, 1, 1, 60, 0, bytes(range(60)))
    emit("fragment_up_r1", "valid", {
        "codec": "authority_fragment", "expect": "ok", "sub": SUB_UP,
        "device": device, "transfer_id": transfer, "kind": 1, "hops": 1,
        "total": 60, "offset": 0, "length": 60, "inner_hex": inner(SUB_UP, r1frag).hex(),
    })
    wake = fragment(device, transfer, 5, 0, 8, 0, u32(7) + u32(11))
    emit("fragment_down_wake", "valid", {
        "codec": "authority_fragment", "expect": "ok", "sub": SUB_DOWN,
        "device": device, "transfer_id": transfer, "kind": 5, "hops": 0,
        "total": 8, "offset": 0, "length": 8,
        "inner_hex": inner(SUB_DOWN, wake).hex(),
    })
    frag_negatives = [
        ("fragment_bad_grid", fragment(device, transfer, 4, 1, 1920, 100, bytes(100)),
         "bad_grid", "offset 100 is not on the 960-byte grid"),
        ("fragment_overlong", fragment(device, transfer, 4, 1, 2048, 0, bytes(960)),
         "length_mismatch", "declared length 961 over the bytes present"),
        ("fragment_over_total", fragment(device, transfer, 4, 1, 100, 0, bytes(101)),
         "length_mismatch", "offset+length passes total"),
        ("fragment_total_too_big", fragment(device, transfer, 4, 1, 2049, 0, bytes(960)),
         "oversized", "total exceeds the 2048-byte envelope ceiling"),
        ("fragment_zero_transfer", fragment(device, 0, 4, 1, 100, 0, bytes(100)),
         "zero_transfer_id", "transfer_id 0 is never valid"),
        ("fragment_bad_kind", fragment(device, transfer, 9, 1, 100, 0, bytes(100)),
         "bad_kind", "kind 9 is undefined"),
        ("fragment_hops_over", fragment(device, transfer, 4, 17, 100, 0, bytes(100)),
         "bad_hops", "hops 17 exceeds the 0..16 range"),
    ]
    for name, payload, reason, note in frag_negatives:
        if name == "fragment_overlong":
            payload = payload[:18] + u16(961) + payload[20:]
        emit(name, "invalid", {
            "codec": "authority_fragment", "expect": "error", "reason": reason,
            "note": note, "inner_hex": inner(SUB_UP, payload).hex(),
        })
    # Down fragments must carry hops 0.
    down_hops = fragment(device, transfer, 4, 1, 100, 0, bytes(100))
    emit("fragment_down_hops_nonzero", "invalid", {
        "codec": "authority_fragment", "expect": "error", "reason": "bad_hops",
        "note": "down fragments must carry hops 0",
        "inner_hex": inner(SUB_DOWN, down_hops).hex(),
    })

    # SiteStateSet (16 B) and SiteStateReport (28 B).
    emit("site_state_set_wake", "valid", {
        "codec": "site_state_set", "expect": "ok", "action": 1,
        "site_epoch": 7, "rs_epoch_hint": 4, "gk_epoch_hint": 11,
        "inner_hex": inner(SUB_SET, u8(1) + u8(1) + u16(0) + u32(7) + u32(4)
                            + u32(11)).hex(),
    })
    emit("site_state_set_query", "valid", {
        "codec": "site_state_set", "expect": "ok", "action": 2,
        "site_epoch": 7, "rs_epoch_hint": 4, "gk_epoch_hint": 11,
        "inner_hex": inner(SUB_SET, u8(1) + u8(2) + u16(0) + u32(7) + u32(4)
                            + u32(11)).hex(),
    })
    emit("site_state_report_queued", "valid", {
        "codec": "site_state_report", "expect": "ok", "result": 1, "flags": 1,
        "device": device, "transfer_id": transfer, "received_len": 2048,
        "local_current": 10, "local_next": 11,
        "inner_hex": inner(SUB_REPORT, u8(1) + u8(1) + u16(1) + u64(device)
                            + u32(transfer) + u16(2048) + u16(0) + u32(10)
                            + u32(11)).hex(),
    })
    set_negatives = [
        ("site_state_set_bad_action",
         inner(SUB_SET, u8(1) + u8(9) + u16(0) + u32(7) + u32(4) + u32(11)),
         "bad_action", "action 9 is undefined"),
        ("site_state_set_reserved",
         inner(SUB_SET, u8(1) + u8(1) + u16(1) + u32(7) + u32(4) + u32(11)),
         "reserved_nonzero", "reserved bits set"),
        ("site_state_report_bad_result",
         inner(SUB_REPORT, u8(1) + u8(9) + u16(0) + u64(device) + u32(transfer)
               + u16(0) + u16(0) + u32(0) + u32(0)),
         "bad_result", "result 9 is undefined"),
        ("site_state_report_bad_flags",
         inner(SUB_REPORT, u8(1) + u8(0) + u16(2) + u64(device) + u32(transfer)
               + u16(0) + u16(0) + u32(0) + u32(0)),
         "reserved_nonzero", "only bit0 local-state-valid is defined"),
    ]
    for name, encoded, reason, note in set_negatives:
        emit(name, "invalid", {
            "codec": "authority_fragment", "expect": "error", "reason": reason,
            "note": note, "inner_hex": encoded.hex(),
        })

    # Mesh carrier heads (kind 1..5) and negatives.
    emit("carrier_r1", "valid", {
        "codec": "authority_carrier", "expect": "ok", "kind": 1,
        "exchange_id": 0x11223344, "head_hex": carrier_head(1, 0x11223344).hex(),
    })
    emit("carrier_envelope", "valid", {
        "codec": "authority_carrier", "expect": "ok", "kind": 4,
        "exchange_id": 0, "head_hex": carrier_head(4, 0).hex(),
    })
    emit("carrier_wake", "valid", {
        "codec": "authority_carrier", "expect": "ok", "kind": 5,
        "exchange_id": 0, "head_hex": carrier_head(5, 0).hex(),
    })
    carrier_negatives = [
        ("carrier_bad_version", b"\x02\x05\x01\x00" + u32(1), "bad_version",
         "carrier version 2"),
        ("carrier_bad_sub", b"\x01\x06\x01\x00" + u32(1), "bad_subtype",
         "subtype 6 is not the authority carrier"),
        ("carrier_bad_kind", b"\x01\x05\x09\x00" + u32(1), "bad_kind",
         "kind 9 is undefined"),
        ("carrier_r1_zero_exchange", carrier_head(1, 0), "zero_exchange_id",
         "kinds 1..3 need a nonzero exchange id"),
        ("carrier_envelope_nonzero_exchange", carrier_head(4, 7), "bad_exchange_id",
         "kinds 4..5 need exchange id 0"),
    ]
    for name, encoded, reason, note in carrier_negatives:
        emit(name, "invalid", {
            "codec": "authority_carrier", "expect": "error", "reason": reason,
            "note": note, "head_hex": encoded.hex(),
        })

    count = len(list((OUT / "valid").glob("*.json"))) + len(list((OUT / "invalid").glob("*.json")))
    print(f"wrote {count} vectors to {OUT}")


if __name__ == "__main__":
    main()
