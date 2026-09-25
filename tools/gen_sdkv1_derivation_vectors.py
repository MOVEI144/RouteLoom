#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/derivations/ (SDK v1 plan P1-4/P1-5).

Independent reference for the FROZEN RouteLoom key-derivation labels and
info encodings of docs/design/sdk-v1/03-key-hierarchy.md §2.2/§5.3/§6.1,
the RLRES1 resume transcript of 06-fast-rejoin.md §2.1, and the dev-RAM
PSK derivations of the P4 design (§10.1). Written from the design text
with the Python standard library only (hmac/hashlib/struct) — it shares
no code with the C++ (components/routeloom/src/key_schedule.cpp,
resume.cpp) or Rust (host/routeloom-keysched) implementations, which must
both reproduce every byte below.

Conventions (frozen):
  * every RouteLoom HKDF info / MAC input starts with an ASCII label
    "RouteLoom/v1/<name>" followed by one 0x00 byte, then fixed-width
    big-endian fields;
  * HKDF is HKDF-SHA-256 (RFC 5869); "first16"/"first8" truncate an
    HMAC-SHA-256 output;
  * a 28-byte key/iv output is key16 || iv12; AEAD nonce is
    iv XOR (zero6 || counter u48).

The fixed inputs below are TEST VALUES (not secrets of any deployment).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden" / "derivations"
FORMAT = "routeloom-sdkv1-derivations-golden"

# --- frozen labels -----------------------------------------------------------
L_GROUP_SALT = b"RouteLoom/v1/group"
L_BCAST = b"RouteLoom/v1/bcast-link"
L_GEND = b"RouteLoom/v1/group-end"
L_DSK = b"RouteLoom/v1/dsk-member"
L_RID = b"RouteLoom/v1/rid"
L_AUTH = b"RouteLoom/v1/resume-auth"
L_BIND = b"RouteLoom/v1/resume-binding"
L_R1 = b"RouteLoom/v1/R1"
L_R2 = b"RouteLoom/v1/R2"
L_R3 = b"RouteLoom/v1/R3"
L_CONF = b"RouteLoom/v1/resume-confirm"
L_KEY = b"RouteLoom/v1/resume-key"
L_DEV_RAM = b"RouteLoom/v1/dev-ram"
L_DEV_RMS = b"RouteLoom/v1/dev-rms"
L_DEV_GROUP_KEY = b"RouteLoom/v1/dev-group-key"
L_DEV_GROUP_IV = b"RouteLoom/v1/dev-group-iv"
L_DEV_SCOPE = b"RouteLoom/v1/dev-scope"

PURPOSE_LINK, PURPOSE_END, PURPOSE_AUTHORITY, PURPOSE_PENDING = 1, 2, 4, 5
DIR_I_TO_R, DIR_R_TO_I = 1, 2
R1_BASE = 60
R1_MAX = 109
R2_OK = 52
R2_HINT = 12
R3_SIZE = 16
TICKET_MAX = 48
ENVELOPE_HEADER = 12
ENVELOPE_MIN = 28
ENVELOPE_MAX = 2048
ENVELOPE_VERSION = 1


def u8(v): return struct.pack(">B", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)
def u48(v): return struct.pack(">Q", v)[2:]


def info(label: bytes, *fields: bytes) -> bytes:
    return label + b"\x00" + b"".join(fields)


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac256(salt, ikm)


def hkdf_expand(prk: bytes, inf: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac256(prk, block + inf + bytes([i]))
        out += block
        i += 1
    return out[:length]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def aead_nonce(iv: bytes, counter: int) -> bytes:
    pad = b"\x00" * 6 + u48(counter)
    return bytes(a ^ b for a, b in zip(iv, pad))


# --- group key (03 §6.1) -----------------------------------------------------

def group_vector(network, gk, g, tx, tx_boot, group_id, origin, session):
    salt = info(L_GROUP_SALT, u64(network))
    prk = hkdf_extract(salt, gk)
    bcast_info = info(L_BCAST, u32(g), u64(tx), u32(tx_boot))
    gend_info = info(L_GEND, u32(g), u64(group_id), u64(origin), u32(session))
    dsk_info = info(L_DSK, u32(g))
    bcast = hkdf_expand(prk, bcast_info, 28)
    gend = hkdf_expand(prk, gend_info, 28)
    dsk = hkdf_expand(prk, dsk_info, 32)
    return {
        "network": network, "gk_hex": gk.hex(), "gk_epoch": g, "tx": tx,
        "tx_boot": tx_boot, "group_id": group_id, "origin": origin,
        "session": session,
        "salt_hex": salt.hex(), "prk_hex": prk.hex(),
        "bcast_info_hex": bcast_info.hex(), "bcast_key_hex": bcast[:16].hex(),
        "bcast_iv_hex": bcast[16:].hex(),
        "gend_info_hex": gend_info.hex(), "gend_key_hex": gend[:16].hex(),
        "gend_iv_hex": gend[16:].hex(),
        "dsk_info_hex": dsk_info.hex(), "dsk_hex": dsk.hex(),
    }


# --- RLRES1 (06 §2.1) --------------------------------------------------------

def resume_id(rms, purpose):
    return hmac256(rms, info(L_RID, u8(purpose)))[:8]


def binding_routed(purpose, node_i, node_r):
    return sha256(info(L_BIND, u8(purpose), u64(node_i), u64(node_r)))


def binding_link(mac_i, mac_r, carrier_digest):
    return sha256(info(L_BIND, u8(PURPOSE_LINK), mac_i, mac_r, carrier_digest))


def r1_body(purpose, rid, nonce_i, cid_i, epochs, ticket):
    body = (u8(purpose) + u8(0) + b"\x00\x00" + rid + nonce_i + u32(cid_i) +
            u32(epochs[0]) + u32(epochs[1]) + u32(epochs[2]))
    if purpose == PURPOSE_PENDING:
        body += u8(len(ticket)) + ticket
    return body


def r2_body(nonce_r, cid_r, epochs):
    return (u8(0) + u8(0) + b"\x00\x00" + nonce_r + u32(cid_r) +
            u32(epochs[0]) + u32(epochs[1]) + u32(epochs[2]))


def r2_hint(status, rid):
    return u8(status) + u8(0) + b"\x00\x00" + rid


def resume_vector(purpose, network, node_i, node_r, rms, nonce_i, nonce_r,
                  cid_i, cid_r, epochs_i, epochs_r, ticket=b"",
                  link=None):
    rid = resume_id(rms, purpose)
    auth_info = info(L_AUTH, u8(purpose), u64(network), u64(node_i), u64(node_r))
    k_auth = hkdf_expand(hkdf_extract(L_AUTH, rms), auth_info, 32)
    if link is not None:
        binding = binding_link(*link)
    else:
        binding = binding_routed(purpose, node_i, node_r)
    body1 = r1_body(purpose, rid, nonce_i, cid_i, epochs_i, ticket)
    r1 = body1 + hmac256(k_auth, info(L_R1, binding, body1))[:16]
    assert len(r1) == R1_BASE + (1 + len(ticket) if purpose == PURPOSE_PENDING else 0)
    body2 = r2_body(nonce_r, cid_r, epochs_r)
    r2 = body2 + hmac256(k_auth, info(L_R2, binding, r1, body2))[:16]
    assert len(r2) == R2_OK
    th = sha256(r1 + r2)
    prk = hkdf_extract(nonce_i + nonce_r, rms)
    conf_info = info(L_CONF, th)
    k_conf = hkdf_expand(prk, conf_info, 32)
    r3 = hmac256(k_conf, info(L_R3, th))[:16]

    def key_info(direction):
        return info(L_KEY, u8(purpose), u8(direction), u64(network), u64(node_i),
                    u64(node_r), u32(cid_i), u32(cid_r), th)

    ir = hkdf_expand(prk, key_info(DIR_I_TO_R), 28)
    ri = hkdf_expand(prk, key_info(DIR_R_TO_I), 28)
    record = {
        "purpose": purpose, "network": network, "node_i": node_i,
        "node_r": node_r, "rms_hex": rms.hex(), "nonce_i_hex": nonce_i.hex(),
        "nonce_r_hex": nonce_r.hex(), "cid_i": cid_i, "cid_r": cid_r,
        "i_site_epoch": epochs_i[0], "i_rs_epoch": epochs_i[1],
        "i_gk_epoch": epochs_i[2], "r_site_epoch": epochs_r[0],
        "r_rs_epoch": epochs_r[1], "r_gk_epoch": epochs_r[2],
        "ticket_hex": ticket.hex(),
        "binding_kind": "link" if link is not None else "routed",
        "rid_hex": rid.hex(), "auth_info_hex": auth_info.hex(),
        "k_auth_hex": k_auth.hex(), "binding_hex": binding.hex(),
        "r1_hex": r1.hex(), "r2_hex": r2.hex(), "th_hex": th.hex(),
        "prk_hex": prk.hex(), "k_conf_hex": k_conf.hex(), "r3_hex": r3.hex(),
        "key_info_ir_hex": key_info(DIR_I_TO_R).hex(),
        "key_ir_hex": ir[:16].hex(), "iv_ir_hex": ir[16:].hex(),
        "key_ri_hex": ri[:16].hex(), "iv_ri_hex": ri[16:].hex(),
    }
    if link is not None:
        record["mac_i_hex"] = link[0].hex()
        record["mac_r_hex"] = link[1].hex()
        record["carrier_digest_hex"] = link[2].hex()
    return record


def envelope_header(version, env_type, ctx_id, counter):
    return u8(version) + u8(env_type) + u32(ctx_id) + u48(counter)


def pattern(seed: int, n: int) -> bytes:
    """Deterministic, obviously-synthetic test bytes."""
    return bytes((seed + 17 * i) & 0xFF for i in range(n))


def emit(sub: str, name: str, record: dict) -> None:
    path = OUT / sub / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


# --- dev-RAM key (P4 §10.1) -------------------------------------------------------
# Same HKDF-SHA-256 shape as the group key, rooted at the shared 32-byte
# development PSK: dev_prk binds the full network id, the pair RMS binds
# the purpose byte plus the ordered node pair, the group key/iv bind the
# origin plus the durable boot, and the discovery scope binds nothing
# further (one fixed generation, boot-independent).

def dev_vector(psk, network, a, b, origin, boot):
    lo, hi = (a, b) if a < b else (b, a)
    salt = info(L_DEV_RAM, u64(network))
    prk = hkdf_extract(salt, psk)
    rms_link_info = info(L_DEV_RMS, u8(PURPOSE_LINK), u64(lo), u64(hi))
    rms_end_info = info(L_DEV_RMS, u8(PURPOSE_END), u64(lo), u64(hi))
    key_info = info(L_DEV_GROUP_KEY, u64(origin), u32(boot))
    iv_info = info(L_DEV_GROUP_IV, u64(origin), u32(boot))
    scope_info = info(L_DEV_SCOPE)
    return {
        "psk_hex": psk.hex(), "network": network, "node_a": a, "node_b": b,
        "origin": origin, "boot": boot,
        "salt_hex": salt.hex(), "prk_hex": prk.hex(),
        "rms_link_info_hex": rms_link_info.hex(),
        "rms_link_hex": hkdf_expand(prk, rms_link_info, 32).hex(),
        "rms_end_info_hex": rms_end_info.hex(),
        "rms_end_hex": hkdf_expand(prk, rms_end_info, 32).hex(),
        "group_key_info_hex": key_info.hex(),
        "group_key_hex": hkdf_expand(prk, key_info, 16).hex(),
        "group_iv_info_hex": iv_info.hex(),
        "group_iv_hex": hkdf_expand(prk, iv_info, 12).hex(),
        "scope_info_hex": scope_info.hex(),
        "scope_hex": hkdf_expand(prk, scope_info, 32).hex(),
    }


def main() -> None:
    # Only the generated folders are wiped; README.md is checked in.
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)

    def good(name, codec, record):
        emit("valid", name, {"format": FORMAT, "name": name, "codec": codec,
                             "expect": "ok", **record})

    def bad(name, codec, encoded, reason, note):
        emit("invalid", name, {"format": FORMAT, "name": name, "codec": codec,
                               "expect": "error", "reason": reason,
                               "note": note, "encoded_hex": encoded.hex()})

    network = (7 << 32) | 0x0A0B0C0D           # site_epoch 7, network_low32
    site_id = 0x5100_0000_0000_0042

    # Group derivations.
    good("group_epoch1", "group",
         group_vector(network, pattern(0x11, 32), 1, 0x0000_0000_0000_0101, 3,
                      0x4700_0000_0000_0001, 0x0000_0000_0000_0102, 9))
    good("group_epoch_max_fields", "group",
         group_vector(0xFFFF_FFFF_FFFF_FFFE, pattern(0xA5, 32), 0xFFFF_FFFF,
                      0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF, 0x4700_0000_0000_00FF,
                      0x0000_0000_0000_0FFF, 0xFFFF_FFFF))

    # Dev-RAM derivations (P4 §10.1, V1-K10): pair RMS per purpose, the
    # boot-scoped group key/iv, and the discovery scope key.
    good("dev_basic", "dev",
         dev_vector(pattern(0x2A, 32), network, 0x0000_0000_0000_0101,
                    0x0000_0000_0000_0102, 0x0000_0000_0000_0101, 7))
    good("dev_max_fields", "dev",
         dev_vector(pattern(0x5A, 32), 0xFFFF_FFFF_FFFF_FFFE,
                    0xFFFF_FFFF_FFFF_FFFD, 0xFFFF_FFFF_FFFF_FFFE,
                    0xFFFF_FFFF_FFFF_FFFD, 0xFFFF_FFFF))

    # AEAD nonce formation (03 §3).
    iv = pattern(0x3C, 12)
    for name, counter in (("nonce_counter_zero", 0), ("nonce_counter_one", 1),
                          ("nonce_counter_max", (1 << 48) - 1)):
        good(name, "aead_nonce", {"iv_hex": iv.hex(), "counter": counter,
                                  "nonce_hex": aead_nonce(iv, counter).hex()})

    ep_i = (7, 3, 12)
    ep_r = (7, 4, 12)
    link = (bytes.fromhex("a0b1c2d3e4f5"), bytes.fromhex("0617283940aa"),
            pattern(0x77, 32))
    good("rlres1_link", "rlres1",
         resume_vector(PURPOSE_LINK, network, 0x101, 0x102, pattern(0x01, 32),
                       pattern(0x21, 16), pattern(0x41, 16), 0x11111111,
                       0x22222222, ep_i, ep_r, link=link))
    good("rlres1_end", "rlres1",
         resume_vector(PURPOSE_END, network, 0x101, 0x001, pattern(0x02, 32),
                       pattern(0x22, 16), pattern(0x42, 16), 0x33333333,
                       0x44444444, ep_i, (7, 3, 13)))
    good("rlres1_authority", "rlres1",
         resume_vector(PURPOSE_AUTHORITY, network, 0x101, site_id,
                       pattern(0x03, 32), pattern(0x23, 16), pattern(0x43, 16),
                       0x55555555, 0x66666666, (7, 2, 10), (7, 4, 12)))
    good("rlres1_pending_join", "rlres1",
         resume_vector(PURPOSE_PENDING, network, 0x1F0, site_id,
                       pattern(0x04, 32), pattern(0x24, 16), pattern(0x44, 16),
                       0x77777777, 0x88888888, (7, 0, 0), (7, 4, 12),
                       ticket=pattern(0x99, TICKET_MAX)))

    rid = resume_id(pattern(0x01, 32), PURPOSE_LINK)
    for status, name in ((1, "unknown_id"), (2, "expired"), (3, "revoked_hint")):
        good(f"rlres1_hint_{name}", "rlres1_hint",
             {"status": status, "rid_hex": rid.hex(),
              "encoded_hex": r2_hint(status, rid).hex()})

    # AuthorityEnvelope header (= AEAD AAD) and nonce with the authority
    # traffic IVs of rlres1_authority (03 §5.3).
    auth = resume_vector(PURPOSE_AUTHORITY, network, 0x101, site_id,
                         pattern(0x03, 32), pattern(0x23, 16), pattern(0x43, 16),
                         0x55555555, 0x66666666, (7, 2, 10), (7, 4, 12))
    for name, env_type, ctx, counter, iv_hex in (
            ("envelope_group_key_pull", 4, 0x66666666, 0, auth["iv_ir_hex"]),
            ("envelope_group_key_update", 2, 0x55555555, 0x0000_0102_0304,
             auth["iv_ri_hex"]),
            ("envelope_time_sample_max_counter", 8, 0x66666666, (1 << 48) - 1,
             auth["iv_ir_hex"])):
        header = envelope_header(ENVELOPE_VERSION, env_type, ctx, counter)
        good(name, "authority_envelope",
             {"version": ENVELOPE_VERSION, "type": env_type, "ctx_id": ctx,
              "counter": counter, "header_hex": header.hex(),
              "iv_hex": iv_hex,
              "nonce_hex": aead_nonce(bytes.fromhex(iv_hex), counter).hex()})

    # --- malformed messages: both decoders must refuse with this reason ----
    link_rec = resume_vector(PURPOSE_LINK, network, 0x101, 0x102,
                             pattern(0x01, 32), pattern(0x21, 16),
                             pattern(0x41, 16), 0x11111111, 0x22222222,
                             ep_i, ep_r, link=link)
    r1 = bytes.fromhex(link_rec["r1_hex"])
    r2 = bytes.fromhex(link_rec["r2_hex"])
    r3 = bytes.fromhex(link_rec["r3_hex"])
    pend = bytes.fromhex(resume_vector(
        PURPOSE_PENDING, network, 0x1F0, site_id, pattern(0x04, 32),
        pattern(0x24, 16), pattern(0x44, 16), 0x77777777, 0x88888888,
        (7, 0, 0), (7, 4, 12), ticket=pattern(0x99, 8))["r1_hex"])

    def patch(msg, offset, value):
        out = bytearray(msg)
        out[offset:offset + len(value)] = value
        return bytes(out)

    bad("r1_truncated", "rlres1_r1", r1[:-1], "truncated", "59 bytes")
    bad("r1_oversized", "rlres1_r1", r1 + pattern(0, 50), "oversized",
        "110 bytes exceeds the 109-byte R1 maximum")
    bad("r1_extra_byte", "rlres1_r1", r1 + b"\x00", "length_mismatch",
        "purpose 1 carries no ticket so R1 is exactly 60 bytes")
    bad("r1_purpose_zero", "rlres1_r1", patch(r1, 0, b"\x00"), "bad_purpose",
        "purpose 0 is unassigned")
    bad("r1_purpose_usb", "rlres1_r1", patch(r1, 0, b"\x03"), "bad_purpose",
        "purpose 3 (usb) is not an RLRES1 purpose")
    bad("r1_flags_set", "rlres1_r1", patch(r1, 1, b"\x01"), "unsupported_flags",
        "no R1 flag is defined in v1")
    bad("r1_reserved_set", "rlres1_r1", patch(r1, 3, b"\x01"),
        "reserved_nonzero", "reserved u16 must be zero")
    bad("r1_zero_cid", "rlres1_r1", patch(r1, 28, b"\x00" * 4),
        "zero_context_id", "cid_I must be non-zero")
    bad("r1_pending_without_ticket", "rlres1_r1",
        patch(r1, 0, u8(PURPOSE_PENDING)), "length_mismatch",
        "purpose 5 must carry ticket_len and a ticket")
    bad("r1_pending_ticket_len_zero", "rlres1_r1",
        patch(pend[:44] + b"\x00" + pend[53:], 0, u8(PURPOSE_PENDING)),
        "ticket_length", "ticket_len must be 1..48")
    bad("r1_pending_ticket_len_over", "rlres1_r1",
        pend[:44] + b"\x31" + pattern(1, 48) + pend[-16:], "ticket_length",
        "ticket_len 49 exceeds 48 (checked before the length agreement)")
    bad("r1_pending_ticket_len_disagrees", "rlres1_r1",
        patch(pend, 44, b"\x09"), "length_mismatch",
        "declared ticket_len disagrees with the bytes present")
    bad("r2_truncated", "rlres1_r2", r2[:11], "truncated", "11 bytes")
    bad("r2_oversized", "rlres1_r2", r2 + b"\x00", "oversized", "53 bytes")
    bad("r2_ok_without_mac", "rlres1_r2", r2[:12], "length_mismatch",
        "status 0 must be the 52-byte authenticated form")
    bad("r2_hint_with_body", "rlres1_r2", patch(r2, 0, b"\x01"),
        "length_mismatch", "status 1 must be the 12-byte hint form")
    bad("r2_bad_status", "rlres1_r2", patch(r2[:12], 0, b"\x04"), "bad_status",
        "status 4 is unassigned")
    bad("r2_flags_set", "rlres1_r2", patch(r2, 1, b"\x80"), "unsupported_flags",
        "no R2 flag is defined in v1")
    bad("r2_reserved_set", "rlres1_r2", patch(r2, 2, b"\x01"),
        "reserved_nonzero", "reserved u16 must be zero")
    bad("r2_zero_cid", "rlres1_r2", patch(r2, 20, b"\x00" * 4),
        "zero_context_id", "cid_R must be non-zero")
    bad("r3_truncated", "rlres1_r3", r3[:15], "truncated", "15 bytes")
    bad("r3_oversized", "rlres1_r3", r3 + b"\x00", "oversized", "17 bytes")
    env = envelope_header(1, 4, 0x66666666, 5) + b"\x00" * 16
    bad("envelope_truncated", "authority_envelope", env[:-1], "truncated",
        "27 bytes is shorter than header plus tag")
    bad("envelope_oversized", "authority_envelope",
        env + b"\x00" * (ENVELOPE_MAX - ENVELOPE_MIN + 1), "oversized",
        "2049 bytes exceeds the 2048-byte object limit")
    bad("envelope_bad_version", "authority_envelope", patch(env, 0, b"\x02"),
        "bad_version", "only version 1 is defined")
    bad("envelope_type_zero", "authority_envelope", patch(env, 1, b"\x00"),
        "bad_type", "type 0 is unassigned")
    bad("envelope_type_nine", "authority_envelope", patch(env, 1, b"\x09"),
        "bad_type", "type 9 is unassigned")
    bad("envelope_zero_ctx", "authority_envelope", patch(env, 2, b"\x00" * 4),
        "zero_context_id", "ctx_id must be non-zero")

    print(f"wrote {len(list((OUT / 'valid').glob('*.json')))} valid and "
          f"{len(list((OUT / 'invalid').glob('*.json')))} invalid vectors to {OUT}")


if __name__ == "__main__":
    main()
