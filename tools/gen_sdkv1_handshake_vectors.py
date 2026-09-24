#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/handshake/ — member session vectors (P4 §5).

Independent reference encoder for the member EDHOC wire of G-SEC P4:
the link carrier digest and link/end bindings (§5.2/§5.3), the session
EAD values SessionIntent/SessionState/ContextConfirm (§5.3) and the
15-element Exporter application contexts with the capability/contexts
digests (§5.4). It shares no code with the C++ codec
(components/routeloom/src/{sdkv1_session_wire,key_schedule}.cpp) or the
Rust mirror (host/routeloom-keysched); all three must agree on every
byte. Only hashlib/hmac/struct from the standard library plus a minimal
CBOR encoder below — no C++/Rust oracle is called.

Member certificates are INPUTS, not issued here: the two signed
MemberCert fixtures of protocol/sdkv1-golden/valid/ (device 0x54 as the
initiator, peer 0x56 as the responder) supply node ids, roles,
generations, networks and cnf kids. No ES256 code lives in this
generator.

The generator also pins the RFC 9528 EDHOC_Exporter KDF itself:
given a fixture PRK_exporter, the info bytes (uint(label) ||
bstr(context) || uint(length)) and the HKDF-SHA-256-Expand output for
the session labels 32768/32769/32770. The LIVE agreement of libedhoc's
own exporter with the Rust implementation is proven by the member
interop exchange (protocol/edhoc-interop/method0_member.txt), not here.

The generator also writes the fuzz seed corpus
tests/fuzz/corpus/sdkv1_handshake/ (the raw EAD values and Exporter
contexts of every valid vector), so the seeds never drift from the
pinned layouts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden" / "handshake"
CORPUS = ROOT / "tests" / "fuzz" / "corpus" / "sdkv1_handshake"
FIXTURES = ROOT / "protocol" / "sdkv1-golden" / "valid"
FMT = "routeloom-sdkv1-handshake-golden-v1"

seeds: list[tuple[str, bytes]] = []


# --- minimal definite-length CBOR encoder (independent) -----------------------


def cbor_uint(value: int) -> bytes:
    assert value >= 0
    if value < 24:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x18, value])
    if value <= 0xFFFF:
        return bytes([0x19]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([0x1A]) + struct.pack(">I", value)
    assert value <= 0xFFFFFFFFFFFFFFFF
    return bytes([0x1B]) + struct.pack(">Q", value)


def cbor_bstr(data: bytes) -> bytes:
    return cbor_head(2, len(data)) + data


def cbor_text(data: bytes) -> bytes:
    return cbor_head(3, len(data)) + data


def cbor_head(major: int, size: int) -> bytes:
    head = cbor_uint(size)
    return bytes([(major << 5) | head[0]]) + head[1:]


def cbor_array(items: list[bytes]) -> bytes:
    return cbor_head(4, len(items)) + b"".join(items)


# --- HKDF-SHA-256 Expand (RFC 5869, for the Exporter cross-check) --------------


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


# --- P4 §5.2/§5.4 digests -------------------------------------------------------


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def prefixed(label: str, *parts: bytes) -> bytes:
    return sha256(label.encode("ascii") + b"\x00", *parts)


def carrier_digest(network: int, node_i: int, node_r: int, nonce_i: bytes, nonce_r: bytes,
                   cookie: bytes, cap_i: int, cap_r: int, scope_binding: bytes) -> bytes:
    assert len(nonce_i) == 16 and len(nonce_r) == 16 and len(cookie) == 16
    assert len(scope_binding) == 32
    return prefixed(
        "RouteLoom/v1/link-carrier",
        b"\x01",
        struct.pack(">QQQ", network, node_i, node_r),
        nonce_i, nonce_r, cookie,
        struct.pack(">II", cap_i, cap_r),
        scope_binding,
    )


def binding_link(mac_i: bytes, mac_r: bytes, digest: bytes) -> bytes:
    assert len(mac_i) == 6 and len(mac_r) == 6 and len(digest) == 32
    return prefixed("RouteLoom/v1/resume-binding", b"\x01", mac_i, mac_r, digest)


def binding_end(network: int, node_i: int, node_r: int, exchange_id: int) -> bytes:
    return prefixed(
        "RouteLoom/v1/end-carrier",
        struct.pack(">QQQI", network, node_i, node_r, exchange_id),
    )


def capability_digest(intent: bytes, state_r: bytes, state_i: bytes) -> bytes:
    assert len(intent) == 44 and len(state_r) == 24 and len(state_i) == 24
    return prefixed("RouteLoom/v1/session-profile", intent, state_r, state_i)


def contexts_digest(dir1: bytes, dir2: bytes, rms: bytes) -> bytes:
    for context in (dir1, dir2, rms):
        assert 0 < len(context) <= 256
    return prefixed(
        "RouteLoom/v1/context-confirm",
        struct.pack(">H", len(dir1)) + dir1,
        struct.pack(">H", len(dir2)) + dir2,
        struct.pack(">H", len(rms)) + rms,
    )


# --- P4 §5.3 EAD values ---------------------------------------------------------


def intent_encode(purpose: int, profile: int, caps_i: int, boot_i: int, binding: bytes) -> bytes:
    assert purpose in (1, 2) and profile == 1 and boot_i != 0 and len(binding) == 32
    assert binding != bytes(32)
    return struct.pack(">BBBBII", 1, purpose, profile, 0, caps_i, boot_i) + binding


def state_encode(purpose: int, profile: int, site: int, rs: int, gk: int, boot: int,
                 caps: int) -> bytes:
    assert purpose in (1, 2) and profile == 1 and boot != 0
    return struct.pack(">BBBBIIIII", 1, purpose, profile, 0, site, rs, gk, boot, caps)


def confirm_encode(purpose: int, profile: int, digest: bytes) -> bytes:
    assert purpose in (1, 2) and profile == 1 and len(digest) == 32
    assert digest != bytes(32)
    return struct.pack(">BBBB", 1, purpose, profile, 0) + digest


# --- P4 §5.4 Exporter application context ---------------------------------------


def exporter_context(purpose: int, network: int, node_i: int, node_r: int, kid_i: bytes,
                     kid_r: bytes, role_i: int, role_r: int, gen_i: int, gen_r: int,
                     context_epoch: int, direction: int, capability: bytes) -> bytes:
    assert purpose in (1, 2) and network != 0 and node_i != node_r
    assert len(kid_i) == 32 and len(kid_r) == 32
    assert role_i != 0 and role_r != 0 and gen_i != 0 and gen_r != 0
    assert direction in (0, 1, 2)
    assert (direction == 0) == (context_epoch == 0)
    assert len(capability) == 32
    context = cbor_array([
        cbor_text(b"RouteLoom"),
        cbor_uint(1),
        cbor_uint(purpose),
        cbor_uint(network),
        cbor_uint(node_i),
        cbor_uint(node_r),
        cbor_bstr(kid_i),
        cbor_bstr(kid_r),
        cbor_uint(role_i),
        cbor_uint(role_r),
        cbor_array([cbor_uint(gen_i), cbor_uint(gen_r)]),
        cbor_array([cbor_uint(2), cbor_uint(0)]),
        cbor_uint(context_epoch),
        cbor_uint(direction),
        cbor_bstr(capability),
    ])
    assert len(context) <= 256, len(context)
    return context


def kdf_info(label: int, context: bytes, length: int) -> bytes:
    return cbor_uint(label) + cbor_bstr(context) + cbor_uint(length)


# --- emission -------------------------------------------------------------------


def emit(folder: str, name: str, record: dict) -> None:
    record = dict(record, format=FMT, name=name)
    path = OUT / folder / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def good(name: str, codec: str, record: dict, **corpus: bytes) -> None:
    emit("valid", name, dict(record, codec=codec, expect="ok"))
    for kind, data in corpus.items():
        seeds.append((f"{name}.{kind}", data))


def bad(name: str, codec: str, encoded: bytes, note: str, **extra) -> None:
    record = dict(codec=codec, encoded_hex=encoded.hex(), expect="error", note=note)
    record.update(extra)
    emit("invalid", name, record)


def main() -> None:
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)
    shutil.rmtree(CORPUS, ignore_errors=True)
    CORPUS.mkdir(parents=True)

    # Member fixtures: device 0x54 is the initiator, peer 0x56 the responder.
    cert_i = json.loads((FIXTURES / "cert_membercert.json").read_text(encoding="utf-8"))
    cert_r = json.loads((FIXTURES / "cert_membercert_peer.json").read_text(encoding="utf-8"))
    assert cert_i["network"] == cert_r["network"] and cert_i["site_epoch"] == cert_r["site_epoch"]
    network = cert_i["network"]
    site_epoch = cert_i["site_epoch"]
    node_i, node_r = cert_i["subject"], cert_r["subject"]
    kid_i = bytes.fromhex(cert_i["subject_kid_hex"])
    kid_r = bytes.fromhex(cert_r["subject_kid_hex"])
    role_i, role_r = cert_i["role"], cert_r["role"]
    gen_i, gen_r = cert_i["assignment_generation"], cert_r["assignment_generation"]

    # --- link carrier (§5.2) ---
    mac_i = bytes.fromhex("020000000001")
    mac_r = bytes.fromhex("020000000002")
    nonce_i = bytes(range(0x10))
    nonce_r = bytes(range(0x10, 0x20))
    cookie = bytes(range(0xA0, 0xB0))
    cap_i = 0x03000000  # MemberEdhocV1 | MemberResumeV1
    cap_r = 0x01000000  # MemberEdhocV1
    scope_binding = bytes.fromhex("11" * 32)
    base_carrier = dict(network=network, node_i=node_i, node_r=node_r, nonce_i=nonce_i,
                        nonce_r=nonce_r, cookie=cookie, cap_i=cap_i, cap_r=cap_r,
                        scope_binding=scope_binding)
    digest = carrier_digest(network, node_i, node_r, nonce_i, nonce_r, cookie, cap_i, cap_r,
                            scope_binding)
    binding = binding_link(mac_i, mac_r, digest)
    base_hex = dict(network=network, node_i=node_i, node_r=node_r,
                    nonce_i_hex=nonce_i.hex(), nonce_r_hex=nonce_r.hex(),
                    cookie_hex=cookie.hex(), cap_i=cap_i, cap_r=cap_r,
                    scope_binding_hex=scope_binding.hex())
    good("carrier_link_basic", "carrier_link",
         dict(base_hex, mac_i_hex=mac_i.hex(), mac_r_hex=mac_r.hex(),
              carrier_digest_hex=digest.hex(), binding_link_hex=binding.hex()))
    full = bytes.fromhex("ff" * 16)
    max_i, max_r = 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFD  # below broadcast
    digest_max = carrier_digest(0xFFFFFFFFFFFFFFFF, max_i, max_r, full, full, full,
                               0xFFFFFFFF, 0xFFFFFFFF, bytes.fromhex("ff" * 32))
    mac_max_i = bytes.fromhex("ffffffffffff")
    mac_max_r = bytes.fromhex("fffffffffffe")
    good("carrier_link_max", "carrier_link",
         dict(network=0xFFFFFFFFFFFFFFFF, node_i=max_i, node_r=max_r,
              nonce_i_hex=full.hex(), nonce_r_hex=full.hex(), cookie_hex=full.hex(),
              cap_i=0xFFFFFFFF, cap_r=0xFFFFFFFF, scope_binding_hex=("ff" * 32),
              mac_i_hex=mac_max_i.hex(), mac_r_hex=mac_max_r.hex(),
              carrier_digest_hex=digest_max.hex(),
              binding_link_hex=binding_link(mac_max_i, mac_max_r, digest_max).hex()))
    flips = [
        ("flip_mac_i", dict(mac_i_hex=bytes.fromhex("020000000009").hex())),
        ("flip_nonce_i", dict(nonce_i_hex=bytes([0xFF] + list(nonce_i[1:])).hex())),
        ("flip_cookie", dict(cookie_hex=bytes([0x00] + list(cookie[1:])).hex())),
        ("flip_cap_r", dict(cap_r=cap_r ^ 0x01000000)),
        ("flip_site", dict(network=((site_epoch + 1) << 32) | (network & 0xFFFFFFFF))),
        ("flip_scope", dict(scope_binding_hex=("22" * 32))),
    ]
    for name, change in flips:
        row = base_hex | change
        row_digest = carrier_digest(
            row["network"], row["node_i"], row["node_r"], bytes.fromhex(row["nonce_i_hex"]),
            bytes.fromhex(row["nonce_r_hex"]), bytes.fromhex(row["cookie_hex"]),
            row["cap_i"], row["cap_r"], bytes.fromhex(row["scope_binding_hex"]))
        row_mac_i = bytes.fromhex(change.get("mac_i_hex", mac_i.hex()))
        row_binding = binding_link(row_mac_i, mac_r, row_digest)
        # The MAC selects the binding, not the digest (§5.2): at least
        # one of the pair must move.
        assert (row_digest, row_binding) != (digest, binding)
        good(f"carrier_{name}", "carrier_link",
             dict(row, mac_i_hex=row_mac_i.hex(), mac_r_hex=mac_r.hex(),
                  carrier_digest_hex=row_digest.hex(), binding_link_hex=row_binding.hex(),
                  differs_from="carrier_link_basic"))

    # --- end binding (§5.3) ---
    exchange_id = 0x12345678
    end = binding_end(network, node_i, node_r, exchange_id)
    good("end_binding_basic", "end_binding",
         dict(network=network, node_i=node_i, node_r=node_r, exchange_id=exchange_id,
              binding_hex=end.hex()))
    end_max = binding_end(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFD,
                          0xFFFFFFFF)
    good("end_binding_max", "end_binding",
         dict(network=0xFFFFFFFFFFFFFFFF, node_i=0xFFFFFFFFFFFFFFFE,
              node_r=0xFFFFFFFFFFFFFFFD, exchange_id=0xFFFFFFFF, binding_hex=end_max.hex()))
    end_flip = binding_end(network, node_i, node_r, exchange_id ^ 1)
    assert end_flip != end
    good("end_binding_flip_exchange", "end_binding",
         dict(network=network, node_i=node_i, node_r=node_r, exchange_id=exchange_id ^ 1,
              binding_hex=end_flip.hex(), differs_from="end_binding_basic"))

    # --- session EAD (§5.3) ---
    boot_i, boot_r = 7, 9
    intent = intent_encode(1, 1, cap_i, boot_i, binding)
    good("intent_link", "session_intent",
         dict(purpose=1, profile=1, caps_i=cap_i, boot_i=boot_i, binding_hex=binding.hex(),
              value_hex=intent.hex()),
         value=intent)
    intent_end = intent_encode(2, 1, 0, boot_i, end)
    good("intent_end", "session_intent",
         dict(purpose=2, profile=1, caps_i=0, boot_i=boot_i, binding_hex=end.hex(),
              value_hex=intent_end.hex()),
         value=intent_end)
    rs_epoch, gk_epoch = 11, 12
    state_r = state_encode(1, 1, site_epoch, rs_epoch, gk_epoch, boot_r, cap_r)
    good("state_responder", "session_state",
         dict(purpose=1, profile=1, site_epoch=site_epoch, rs_epoch=rs_epoch,
              gk_epoch=gk_epoch, boot=boot_r, caps=cap_r, value_hex=state_r.hex()),
         value=state_r)
    state_i = state_encode(1, 1, site_epoch, rs_epoch, gk_epoch, boot_i, cap_i)
    good("state_initiator", "session_state",
         dict(purpose=1, profile=1, site_epoch=site_epoch, rs_epoch=rs_epoch,
              gk_epoch=gk_epoch, boot=boot_i, caps=cap_i, value_hex=state_i.hex()),
         value=state_i)
    state_max = state_encode(2, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    good("state_max", "session_state",
         dict(purpose=2, profile=1, site_epoch=0xFFFFFFFF, rs_epoch=0xFFFFFFFF,
              gk_epoch=0xFFFFFFFF, boot=0xFFFFFFFF, caps=0xFFFFFFFF,
              value_hex=state_max.hex()),
         value=state_max)

    # --- Exporter contexts (§5.4) ---
    capability = capability_digest(intent, state_r, state_i)
    good("capability_basic", "capability_digest",
         dict(intent_hex=intent.hex(), state_r_hex=state_r.hex(), state_i_hex=state_i.hex(),
              digest_hex=capability.hex()))
    cid_i, cid_r = 0x2C7F1A09, 0x5A17C0DE
    dir1 = exporter_context(1, network, node_i, node_r, kid_i, kid_r, role_i, role_r, gen_i,
                            gen_r, cid_r, 1, capability)
    dir2 = exporter_context(1, network, node_i, node_r, kid_i, kid_r, role_i, role_r, gen_i,
                            gen_r, cid_i, 2, capability)
    rms_ctx = exporter_context(1, network, node_i, node_r, kid_i, kid_r, role_i, role_r,
                               gen_i, gen_r, 0, 0, capability)
    params = dict(purpose=1, network=network, node_i=node_i, node_r=node_r,
                  kid_i_hex=kid_i.hex(), kid_r_hex=kid_r.hex(), role_i=role_i, role_r=role_r,
                  generation_i=gen_i, generation_r=gen_r, capability_hex=capability.hex(),
                  intent_hex=intent.hex(), state_r_hex=state_r.hex(),
                  state_i_hex=state_i.hex())
    good("exporter_dir1", "exporter_context",
         dict(params, context_epoch=cid_r, direction=1, context_hex=dir1.hex(),
              context_len=len(dir1)),
         context=dir1)
    good("exporter_dir2", "exporter_context",
         dict(params, context_epoch=cid_i, direction=2, context_hex=dir2.hex(),
              context_len=len(dir2)),
         context=dir2)
    good("exporter_rms", "exporter_context",
         dict(params, context_epoch=0, direction=0, context_hex=rms_ctx.hex(),
              context_len=len(rms_ctx)),
         context=rms_ctx)
    ctx_max = exporter_context(2, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE,
                               0xFFFFFFFFFFFFFFFD, bytes.fromhex("ab" * 32),
                               bytes.fromhex("cd" * 32), 0xFFFFFFFF, 0xFFFFFFFF,
                               0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 1,
                               bytes.fromhex("ef" * 32))
    good("exporter_max", "exporter_context",
         dict(purpose=2, network=0xFFFFFFFFFFFFFFFF, node_i=0xFFFFFFFFFFFFFFFE,
              node_r=0xFFFFFFFFFFFFFFFD, kid_i_hex="ab" * 32, kid_r_hex="cd" * 32,
              role_i=0xFFFFFFFF, role_r=0xFFFFFFFF, generation_i=0xFFFFFFFF,
              generation_r=0xFFFFFFFF, context_epoch=0xFFFFFFFF, direction=1,
              capability_hex="ef" * 32, context_hex=ctx_max.hex(),
              context_len=len(ctx_max)),
         context=ctx_max)
    flip_ctx = exporter_context(1, network, node_i, node_r, kid_i, kid_r, role_i, role_r,
                                gen_i, gen_r, cid_r ^ 1, 1, capability)
    assert flip_ctx != dir1
    good("exporter_flip_epoch", "exporter_context",
         dict(params, context_epoch=cid_r ^ 1, direction=1, context_hex=flip_ctx.hex(),
              context_len=len(flip_ctx), differs_from="exporter_dir1"))
    digests = contexts_digest(dir1, dir2, rms_ctx)
    good("contexts_digest_basic", "contexts_digest",
         dict(dir1_hex=dir1.hex(), dir2_hex=dir2.hex(), rms_hex=rms_ctx.hex(),
              digest_hex=digests.hex()))
    confirm = confirm_encode(1, 1, digests)
    good("confirm_basic", "context_confirm",
         dict(purpose=1, profile=1, digest_hex=digests.hex(), value_hex=confirm.hex()),
         value=confirm)
    confirm_max = confirm_encode(2, 1, bytes.fromhex("ff" * 32))
    good("confirm_max", "context_confirm",
         dict(purpose=2, profile=1, digest_hex="ff" * 32, value_hex=confirm_max.hex()),
         value=confirm_max)

    # --- EDHOC_Exporter from a known PRK (RFC 9528 §4.2.1) ---
    prk = bytes.fromhex("4a" * 32)
    for name, label, context, length in (("key", 32768, dir1, 16),
                                         ("iv", 32769, dir1, 12),
                                         ("rms", 32770, rms_ctx, 32)):
        info = kdf_info(label, context, length)
        out = hkdf_expand(prk, info, length)
        good(f"exporter_output_{name}", "exporter_output",
             dict(prk_hex=prk.hex(), label=label, context_hex=context.hex(), length=length,
                  info_hex=info.hex(), output_hex=out.hex()))

    # --- invalid EAD values (§5.3: unknown/duplicated shapes refused) ---
    bad("intent_bad_version", "session_intent", b"\x02" + intent[1:],
        "ver must be 1")
    bad("intent_bad_purpose", "session_intent", intent[:1] + b"\x03" + intent[2:],
        "purpose is 1 link or 2 end")
    bad("intent_bad_profile", "session_intent", intent[:2] + b"\x02" + intent[3:],
        "profile 2 (DevRam) is PR6, refused in PR2")
    bad("intent_bad_flags", "session_intent", intent[:3] + b"\x01" + intent[4:],
        "flags must be 0")
    bad("intent_zero_boot", "session_intent", intent[:8] + b"\x00\x00\x00\x00" + intent[12:],
        "boot is nonzero")
    bad("intent_zero_binding", "session_intent", intent[:12] + bytes(32),
        "binding is a digest, never zero")
    bad("intent_truncated", "session_intent", intent[:-1], "44 B exact")
    bad("intent_extended", "session_intent", intent + b"\x00", "44 B exact")
    bad("state_bad_version", "session_state", b"\x02" + state_r[1:], "ver must be 1")
    bad("state_bad_purpose", "session_state", state_r[:1] + b"\x00" + state_r[2:],
        "purpose is 1 link or 2 end")
    bad("state_bad_profile", "session_state", state_r[:2] + b"\x09" + state_r[3:],
        "profile must be 1")
    bad("state_bad_flags", "session_state", state_r[:3] + b"\x80" + state_r[4:],
        "flags must be 0")
    bad("state_zero_boot", "session_state", state_r[:16] + b"\x00\x00\x00\x00" + state_r[20:],
        "boot is nonzero")
    bad("state_truncated", "session_state", state_r[:-1], "24 B exact")
    bad("state_extended", "session_state", state_r + b"\x00", "24 B exact")
    bad("confirm_bad_version", "context_confirm", b"\x02" + confirm[1:], "ver must be 1")
    bad("confirm_bad_purpose", "context_confirm", confirm[:1] + b"\x09" + confirm[2:],
        "purpose is 1 link or 2 end")
    bad("confirm_bad_profile", "context_confirm", confirm[:2] + b"\x00" + confirm[3:],
        "profile must be 1")
    bad("confirm_bad_flags", "context_confirm", confirm[:3] + b"\x02" + confirm[4:],
        "flags must be 0")
    bad("confirm_zero_digest", "context_confirm", confirm[:4] + bytes(32),
        "digest is a hash, never zero")
    bad("confirm_truncated", "context_confirm", confirm[:-1], "36 B exact")
    bad("confirm_extended", "context_confirm", confirm + b"\x00", "36 B exact")

    (OUT / "README.md").write_text(README, encoding="utf-8")
    for name, data in seeds:
        (CORPUS / name).write_bytes(data)


README = """# Member session handshake golden vectors (P4 §5)

Byte-exact vectors for the member EDHOC wire of G-SEC P4: the link
carrier digest and link/end bindings (§5.2/§5.3), the session EAD values
SessionIntent (−65542), SessionState (−65543), ContextConfirm (−65544)
(§5.3), the 15-element Exporter application contexts with the
capability/contexts digests (§5.4), and the RFC 9528 EDHOC_Exporter KDF
from a known PRK_exporter.

| side | code | what it does with the vectors |
|---|---|---|
| generator | `tools/gen_sdkv1_handshake_vectors.py` | independent reference encoder from the design text; stdlib only, no C++/Rust oracle; member certificates are inputs from `protocol/sdkv1-golden/valid/cert_membercert{,_peer}.json` |
| C++ | `components/routeloom/src/{sdkv1_session_wire,key_schedule}.cpp`, test `tests/cpp/test_sdkv1_session_wire.cpp` | encode/decode, digest agreement, KDF-info + HKDF-Expand outputs, invalid-shape refusal |
| Rust | `host/routeloom-keysched`, test `host/routeloom-keysched/tests/golden.rs` | the same on the mirror codecs |

Regenerate with `python3 tools/gen_sdkv1_handshake_vectors.py`; CI
regenerates and requires `git diff --exit-code` plus no untracked files
here. The same run rewrites the fuzz seeds
`tests/fuzz/corpus/sdkv1_handshake/` (raw EAD values and Exporter
contexts of every valid vector).

Member fixtures: initiator = device `0x54` (`cert_membercert.json`,
role Endpoint, generation 3), responder = peer `0x56`
(`cert_membercert_peer.json`, role Relay, generation 1); network
`0x000000030A1B2C3D` (site epoch 3). `*_flip_*` vectors change exactly
one input field and must both match byte-for-byte and differ from the
base vector named in `differs_from`.

Layouts pinned here (integers big-endian, all-unknown refused):

- `carrier_digest = SHA-256("RouteLoom/v1/link-carrier" || 00 ||
  rld1_version_u8(1) || full_network_u64 || node_I_u64 || node_R_u64 ||
  requester_nonce16 || responder_nonce16 || cookie16 || capability_I_u32
  || capability_R_u32 || scope_binding32)`; `binding_link =
  SHA-256("RouteLoom/v1/resume-binding" || 00 || 01 || MAC_I6 || MAC_R6
  || carrier_digest32)`; end binding =
  `SHA-256("RouteLoom/v1/end-carrier" || 00 || full_network_u64 ||
  node_I_u64 || node_R_u64 || exchange_id_u32)`.
- SessionIntent (44 B): `ver=1 u8 || purpose u8(1/2) || profile u8=1 ||
  flags u8=0 || caps_I u32 || boot_I u32(nonzero) || binding32`.
- SessionState (24 B): `ver/purpose/profile/flags || site_epoch u32 ||
  rs_epoch u32 || gk_epoch u32 || boot u32(nonzero) || caps u32`.
- ContextConfirm (36 B): `ver/purpose/profile/flags || contexts_digest32`.
- Exporter context: the 15-element definite-length CBOR array
  `["RouteLoom", 1, purpose, full_network, node_I, node_R, kid_I:bstr32,
  kid_R:bstr32, role_I:u32, role_R:u32, [gen_I, gen_R], [2, 0],
  context_epoch:u32, direction:u8, capability_digest:bstr32]`, ≤ 256 B.
- `capability_digest = SHA-256("RouteLoom/v1/session-profile" || 00 ||
  Intent44 || State_R24 || State_I24)`; `contexts_digest =
  SHA-256("RouteLoom/v1/context-confirm" || 00 || len16(C_1) || C_1 ||
  len16(C_2) || C_2 || len16(C_RMS) || C_RMS)`.
- `EDHOC_Exporter(PRK, label, context, L) = HKDF-Expand(PRK,
  uint(label) || bstr(context) || uint(L), L)` (RFC 9528 §4.2.1).
"""


if __name__ == "__main__":
    main()
