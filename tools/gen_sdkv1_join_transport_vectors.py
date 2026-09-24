#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/join-transport/ — SDK v1 join transport vectors (P3-1/P3-2).

Independent reference encoder for the zero-touch join transport of
docs/design/sdk-v1/02-zero-touch-join.md §5 (RLD1 body v3 DISCOVER/OFFER,
BootstrapAuth phases 4-6, the <= 1024 B assembly object and its chunks and
replies), as resolved in 02 §5.4 / §7.4 and
protocol/sdkv1-golden/join-transport/README.md. The Wire relay lane v2
(#116: 32 B objects, 18 B chunks/replies, epoch query/reply) moved to
tools/gen_sdkv1_join_relay_v2_vectors.py; the v1-shaped invalid vectors
kept here must still be refused by the v2 decoders.
It shares no code with the C++ codecs (components/routeloom/src/
sdkv1_join_transport.cpp, sdkv1_join_relay.cpp) or the Rust relay-object
mirror (host/routeloom-protocol/src/join_relay.rs); they must agree on every
byte. The only helper borrowed is the P-256 public-key function of the
sibling tools/gen_sdkv1_vectors.py, to derive the org_hint of the test Site CA.

EDHOC / RLRES1 message bytes here are opaque filler of realistic lengths:
the transport never parses them (the P2-1 EDHOC backend and the P2-3 EAD
vectors pin those bytes).

The generator also writes the fuzz seed corpus tests/fuzz/corpus/sdkv1_join/
(raw codec inputs, and length-prefixed frame scripts of complete exchanges
for the engine half of fuzz_sdkv1_join).
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden" / "join-transport"
CORPUS = ROOT / "tests" / "fuzz" / "corpus" / "sdkv1_join"
FMT = "routeloom-sdkv1-join-transport-golden-v1"

_spec = importlib.util.spec_from_file_location(
    "gen_sdkv1_vectors", Path(__file__).resolve().parent / "gen_sdkv1_vectors.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)  # type: ignore[union-attr]


def u8(v: int) -> bytes: return struct.pack(">B", v)
def i8(v: int) -> bytes: return struct.pack(">b", v)
def u16(v: int) -> bytes: return struct.pack(">H", v)
def u32(v: int) -> bytes: return struct.pack(">I", v)
def u64(v: int) -> bytes: return struct.pack(">Q", v)


# --- constants of the design as resolved ------------------------------------------------
RLD1_HEADER, RLD1_MAX_BODY = 44, 116
WIRE_MAX_PAYLOAD = 128
OBJECT_MAX, MESSAGE_MAX = 1024, 960
CHUNK_HEAD = 10
GRID = {"rld1": RLD1_MAX_BODY - CHUNK_HEAD, "wire": WIRE_MAX_PAYLOAD - CHUNK_HEAD}  # 106 / 118
SINGLE_MAX = {"rld1": RLD1_MAX_BODY, "wire": WIRE_MAX_PAYLOAD}
KIND = {"discover": 1, "offer": 2, "auth": 3, "result": 4, "chunk": 5, "reply": 6}
EDHOC, RESUME, RELAY_STATUS = 4, 5, 6
UP, DOWN = 1, 2
CONTINUE, FINAL, ABORT = 0, 1, 2
QUEUED, UNREACHABLE, BUSY, ABORTED = 1, 2, 3, 4
RETRY_MAX = 600000
COOKIE_DOMAIN = b"RouteLoom/zt-cookie/v1\x00"

# Test identities (TEST MATERIAL): the same site/nodes as the EAD vectors.
DEVICE, DEVICE_MAC = 0x00A1000000001234, bytes.fromhex("020000001234")
PROXY, PROXY_MAC = 0x00A1000000000777, bytes.fromhex("020000000777")
GATEWAY = 0x00A1000000000001
SITE_ID, NETWORK_LOW32 = 0x5173000000000042, 0x0A1B2C3D
NONCE = bytes(range(0x10, 0x20))
BROADCAST = b"\xff" * 6


def first4(data: bytes) -> int:
    return struct.unpack(">I", hashlib.sha256(data).digest()[:4])[0]


ORG_HINT = first4(b"RouteLoom/org-hint/v1\x00" + base.pubkey(base.seed(0x52)))
SITE_HINT = first4(b"RouteLoom/site-hint/v1\x00" + u64(SITE_ID))


def filler(label: str, size: int) -> bytes:
    """Deterministic opaque message bytes (never parsed by the transport)."""
    out, counter = b"", 0
    while len(out) < size:
        out += hashlib.sha256(f"RouteLoom/join-transport/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:size]


# --- encoders straight from the layouts ---------------------------------------------------
def rld1(kind: int, network_hint: int, claimed: int, nonce: bytes, body: bytes,
         capability: int = 0, flags: int = 0) -> bytes:
    total = RLD1_HEADER + len(body)
    return (b"RLD1" + u8(1) + u8(kind) + u16(RLD1_HEADER) + u16(total) + u16(flags) +
            u32(network_hint) + u64(claimed) + nonce + u32(capability) + body)


def discover_body(profile: int, org: int, preferred: int = 0, avoid=(0, 0),
                  version: int = 3, cls: int = 3, flags: int | None = None) -> bytes:
    if flags is None:
        flags = 1 if preferred else 0
    return (u8(version) + u8(cls) + u16(flags) + u32(profile) + u32(org) + u32(preferred) +
            u32(avoid[0]) + u32(avoid[1]))


def offer_body(density: int, flags: int, cookie: bytes, responder_nonce: bytes, org: int,
               site: int, hops: int, load: int, reserved: int = 0, version: int = 3,
               cls: int = 3) -> bytes:
    return (u8(version) + u8(cls) + u8(density) + u8(flags) + cookie + responder_nonce +
            u32(org) + u32(site) + u8(hops) + u8(load) + u16(reserved))


def join_object(phase: int, step: int, message: bytes = b"", cookie: bytes | None = None,
                version: int = 1, reserved: int = 0, flag: int | None = None,
                head_reserved: int = 0) -> bytes:
    prefix = u8(version) + u8(phase) + u8(step) + u8(reserved)
    if flag is None:
        flag = 1 if cookie is not None else 0
    return prefix + u8(flag) + u8(head_reserved) + (cookie or b"") + message


def relay_status_object(status: int, retry: int, step: int = 1) -> bytes:
    return u8(1) + u8(RELAY_STATUS) + u8(step) + u8(0) + u8(status) + u32(retry)


def sub(phase: int, step: int) -> int:
    return (phase << 4) | step


def chunk(phase: int, step: int, ident: int, offset: int, total: int, data: bytes,
          version: int = 1, sub_override: int | None = None) -> bytes:
    s = sub(phase, step) if sub_override is None else sub_override
    return u8(version) + u8(s) + u32(ident) + u16(offset) + u16(total) + data


def reply(phase: int, step: int, ident: int, received: int, status: int, reserved: int = 0,
          version: int = 1) -> bytes:
    return u8(version) + u8(sub(phase, step)) + u32(ident) + u16(received) + u8(status) + u8(reserved)


def chunks_of(carrier: str, obj: bytes, phase: int, step: int, ident: int) -> list[bytes]:
    grid, out = GRID[carrier], []
    assert SINGLE_MAX[carrier] < len(obj) <= OBJECT_MAX
    for offset in range(0, len(obj), grid):
        out.append(chunk(phase, step, ident, offset, len(obj), obj[offset:offset + grid]))
    return out


def relay_header(direction: int, relay_id: int, proxy: int, mac: bytes, step: int, state: int,
                 rssi: int, phase: int, version: int = 1) -> bytes:
    return (u8(version) + u8(direction) + u32(relay_id) + u64(proxy) + mac + u8(step) +
            u8(state) + i8(rssi) + u8(phase))


def relay_object(direction, relay_id, proxy, mac, phase, step, state, rssi, message=b"",
                 abort=None) -> bytes:
    body = message if abort is None else u8(abort[0]) + u32(abort[1])
    return relay_header(direction, relay_id, proxy, mac, step, state, rssi, phase) + body


def single_type(direction: int, state: int) -> int:
    return KIND["result"] if direction == DOWN and state != CONTINUE else KIND["auth"]


def cookie(key: bytes, mac: bytes, nonce: bytes, proxy: int, network: int, bucket: int) -> bytes:
    data = COOKIE_DOMAIN + mac + nonce + u64(proxy) + u32(network) + u64(bucket)
    return hmac.new(key, data, hashlib.sha256).digest()[:16]


# --- emit -----------------------------------------------------------------------------------
seeds: list[tuple[str, bytes]] = []
counts = {"valid": 0, "invalid": 0}


def emit(folder: str, name: str, record: dict) -> None:
    record = dict(record, format=FMT, name=name)
    path = OUT / folder / f"{name}.json"
    assert not path.exists(), name
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts[folder] += 1


def good(name: str, codec: str, record: dict, *seed_bytes: bytes) -> None:
    emit("valid", name, dict(record, codec=codec, expect="ok"))
    for i, data in enumerate(seed_bytes):
        seeds.append((f"{name}.{i}", data))


def bad(name: str, codec: str, encoded: bytes, note: str, **extra) -> None:
    record = dict(codec=codec, encoded_hex=encoded.hex(), expect="error", note=note)
    record.update(extra)
    emit("invalid", name, record)


def script(frames: list[bytes]) -> bytes:
    """Length-prefixed frame script for the engine half of the fuzz target."""
    return b"".join(u16(len(f)) + f for f in frames)


# --- valid vectors -------------------------------------------------------------------------
def valid_discovery() -> list[bytes]:
    frames = []
    for name, profile, preferred, avoid, note in (
            ("zt_discover_minimal", 1, 0, (0, 0), "RLJOIN1 only, no site preference"),
            ("zt_discover_resume_profile", 3, 0, (0, 0), "RLJOIN1 + RLRES1"),
            ("zt_discover_preferred_avoid", 3, 0x11223344, (SITE_HINT ^ 1, 0x55667788),
             "preferred site plus two avoided sites (flags bit0 derived)"),
            ("zt_discover_one_avoid", 1, 0, (0x0BADF00D, 0), "one avoided site")):
        body = discover_body(profile, ORG_HINT, preferred, avoid)
        frame = rld1(KIND["discover"], 0, DEVICE, NONCE, body)
        good(name, "zt_discover_frame",
             dict(frame_hex=frame.hex(), claimed_node=DEVICE, nonce_hex=NONCE.hex(),
                  profile_bits=profile, org_hint=ORG_HINT, preferred_site_hint=preferred,
                  avoid0=avoid[0], avoid1=avoid[1], body_hex=body.hex(), note=note),
             frame, body)
        frames.append(frame)
    key = bytes([0x5A] * 32)
    for name, flags, hops, load, density, bucket, note in (
            ("zt_offer_reachable", 1, 2, 0, 1, 0, "authority reachable, 2 hops"),
            ("zt_offer_busy_unknown_hops", 3, 255, 200, 5, 7, "proxy busy hint, hops unknown")):
        ck = cookie(key, DEVICE_MAC, NONCE, PROXY, NETWORK_LOW32, bucket)
        rn = bytes(range(0xA0, 0xB0))
        body = offer_body(density, flags, ck, rn, ORG_HINT, SITE_HINT, hops, load)
        frame = rld1(KIND["offer"], NETWORK_LOW32, PROXY, NONCE, body)
        good(name, "zt_offer_frame",
             dict(frame_hex=frame.hex(), proxy=PROXY, network_low32=NETWORK_LOW32,
                  nonce_hex=NONCE.hex(), density=density, flags=flags, cookie_hex=ck.hex(),
                  responder_nonce_hex=rn.hex(), org_hint=ORG_HINT, site_hint=SITE_HINT,
                  authority_hops=hops, load=load, body_hex=body.hex(), note=note),
             frame, body)
        frames.append(frame)
    return frames


def valid_cookies() -> None:
    for name, key, bucket in (("cookie_bucket_0", bytes([0x5A] * 32), 0),
                              ("cookie_bucket_large", bytes(range(32)), 0x0123456789)):
        ck = cookie(key, DEVICE_MAC, NONCE, PROXY, NETWORK_LOW32, bucket)
        good(name, "cookie",
             dict(key_hex=key.hex(), mac_hex=DEVICE_MAC.hex(), nonce_hex=NONCE.hex(),
                  proxy=PROXY, network_low32=NETWORK_LOW32, bucket=bucket, cookie_hex=ck.hex(),
                  note="HmacJoinCookie: first16(HMAC-SHA-256(key, domain||mac||nonce||proxy||"
                       "network_low32||bucket))"))


def valid_objects() -> None:
    ck = bytes(range(0xC0, 0xD0))
    cases = [
        ("join_object_m1", EDHOC, 1, filler("m1", 59), ck, "m1 with the cookie echo, one RLD1 frame"),
        ("join_object_m2", EDHOC, 2, filler("m2", 372), None, "m2 (SiteCert in EAD_2)"),
        ("join_object_m3", EDHOC, 3, filler("m3", 404), None, "m3 (DevCert in EAD_3)"),
        ("join_object_m4", EDHOC, 4, filler("m4", 353), None, "m4 allow"),
        ("join_object_error_up", EDHOC, 5, filler("err", 3), None, "EDHOC error"),
        ("join_object_r1_cookie", RESUME, 1, filler("r1", 109), ck, "R1 with ticket and cookie"),
        ("join_object_r1_no_cookie", RESUME, 1, filler("r1s", 60), None, "R1 without cookie"),
        ("join_object_r2", RESUME, 2, filler("r2", 52), None, "R2"),
        ("join_object_r3", RESUME, 3, filler("r3", 16), None, "R3"),
        ("join_object_max", EDHOC, 1, filler("max", MESSAGE_MAX), ck, "960 B message + cookie"),
    ]
    for name, phase, step, message, ck_value, note in cases:
        obj = join_object(phase, step, message, ck_value)
        good(name, "join_object",
             dict(object_hex=obj.hex(), phase=phase, step=step,
                  cookie_present=1 if ck_value else 0, cookie_hex=(ck_value or b"").hex(),
                  message_hex=message.hex(), relay_status=0, retry_after_ms=0, note=note),
             obj)
    for status, retry in ((QUEUED, 0), (UNREACHABLE, 5000), (BUSY, 2000), (ABORTED, RETRY_MAX)):
        obj = relay_status_object(status, retry)
        good(f"join_object_relay_status_{status}", "join_object",
             dict(object_hex=obj.hex(), phase=RELAY_STATUS, step=1, cookie_present=0,
                  cookie_hex="", message_hex="", relay_status=status, retry_after_ms=retry,
                  note="RelayStatus hint (9 B)"),
             obj)


def rld1_sequence(name: str, obj: bytes, phase: int, step: int, sender: str, note: str) -> list[bytes]:
    ident = struct.unpack(">I", NONCE[:4])[0]
    from_device = sender == "device"
    claimed, hint = (DEVICE, 0) if from_device else (PROXY, NETWORK_LOW32)
    peer_claimed, peer_hint = (PROXY, NETWORK_LOW32) if from_device else (DEVICE, 0)
    record = dict(object_hex=obj.hex(), carrier="rld1", phase=phase, step=step, object_id=ident,
                  sender=sender, claimed_node=claimed, network_hint=hint,
                  nonce_hex=NONCE.hex(), note=note)
    frames = []
    if len(obj) <= RLD1_MAX_BODY:
        frames.append(rld1(KIND["auth"], hint, claimed, NONCE, obj))
        record["frame_count"] = 1
        record["frame_00_hex"] = frames[0].hex()
        record["reply_count"] = 0
    else:
        parts = chunks_of("rld1", obj, phase, step, ident)
        record["frame_count"] = len(parts)
        received = 0
        replies = []
        for i, part in enumerate(parts):
            frame = rld1(KIND["chunk"], hint, claimed, NONCE, part)
            frames.append(frame)
            record[f"frame_{i:02d}_hex"] = frame.hex()
            received += len(part) - CHUNK_HEAD
            status = 1 if received == len(obj) else 0
            replies.append(rld1(KIND["reply"], peer_hint, peer_claimed, NONCE,
                                reply(phase, step, ident, received, status)))
            record[f"reply_{i:02d}_hex"] = replies[-1].hex()
        record["reply_count"] = len(replies)
    good(name, "rld1_object_frames", record, *frames)
    return frames


def valid_rld1_sequences() -> list[bytes]:
    ck = bytes(range(0xC0, 0xD0))
    script_frames = []
    script_frames += rld1_sequence("rld1_m1_single", join_object(EDHOC, 1, filler("m1", 59), ck),
                                   EDHOC, 1, "device", "m1 fits one BootstrapAuth frame (81 B body)")
    script_frames += rld1_sequence("rld1_m2_chunked", join_object(EDHOC, 2, filler("m2", 372)),
                                   EDHOC, 2, "proxy", "m2: 378 B object, 4 chunks + 4 replies")
    script_frames += rld1_sequence("rld1_m3_chunked", join_object(EDHOC, 3, filler("m3", 404)),
                                   EDHOC, 3, "device", "m3: 410 B object, 4 chunks")
    rld1_sequence("rld1_r1_chunked", join_object(RESUME, 1, filler("r1", 109), ck), RESUME, 1,
                  "device", "R1 + ticket + cookie = 131 B: the cookie rides chunk 0")
    rld1_sequence("rld1_max_object", join_object(EDHOC, 1, filler("max", MESSAGE_MAX), ck),
                  EDHOC, 1, "device", "largest object: 982 B, 10 chunks")
    rld1_sequence("rld1_relay_status", relay_status_object(BUSY, 2000), RELAY_STATUS, 1, "proxy",
                  "RelayStatus busy")
    return script_frames


def valid_chunk_codecs() -> None:
    ident = 0x10111213
    obj = join_object(EDHOC, 2, filler("m2", 372))
    for i, part in enumerate(chunks_of("rld1", obj, EDHOC, 2, ident)):
        good(f"join_chunk_rld1_{i}", "join_chunk",
             dict(payload_hex=part.hex(), carrier="rld1", phase=EDHOC, step=2, id=ident,
                  offset=i * GRID["rld1"], total=len(obj), data_hex=part[CHUNK_HEAD:].hex(),
                  note="grid 106 B"), part)
    # The Wire lane moved to v2 (#116: 18 B chunks/replies with epochs);
    # its vectors live in join-relay-v2 (tools/gen_sdkv1_join_relay_v2_vectors.py).
    # These 10 B replies are the RLD1 shape, tagged as such.
    for name, phase, step, ident2, received, status in (
            ("join_reply_progress", EDHOC, 2, ident, 212, 0),
            ("join_reply_complete", EDHOC, 3, ident, 410, 1),
            ("join_reply_aborted", RESUME, 1, 0xBEEF, 0, 2)):
        payload = reply(phase, step, ident2, received, status)
        good(name, "join_reply",
             dict(payload_hex=payload.hex(), carrier="rld1", phase=phase, step=step, id=ident2,
                  received=received, status=status, note="10 B RLD1 reply"), payload)


# NOTE (#116): valid Wire relay objects moved to join-relay-v2
# (tools/gen_sdkv1_join_relay_v2_vectors.py); the v1 bytes below only feed
# the invalid vectors, which the v2 decoders must still refuse.


# --- invalid vectors -----------------------------------------------------------------------
def invalid_discovery() -> None:
    good_body = discover_body(1, ORG_HINT)

    def dbad(name, body, note, **header):
        h = dict(network_hint=0, claimed=DEVICE, capability=0, kind=KIND["discover"])
        h.update(header)
        frame = rld1(h["kind"], h["network_hint"], h["claimed"], NONCE, body, h["capability"])
        bad(name, "zt_discover_frame", frame, note)

    dbad("zt_discover_body_version_2", discover_body(1, ORG_HINT, version=2), "body v2 is the scoped lane")
    dbad("zt_discover_class_member", discover_body(1, ORG_HINT, cls=1), "class must be ZeroTouch (3)")
    dbad("zt_discover_flag_without_hint", discover_body(1, ORG_HINT, flags=1),
         "preferred_site_valid needs a nonzero hint")
    dbad("zt_discover_hint_without_flag", discover_body(1, ORG_HINT, 0x1234, flags=0),
         "a preferred hint needs flags bit0")
    dbad("zt_discover_unknown_flag", discover_body(1, ORG_HINT, flags=2), "unknown flag bit")
    dbad("zt_discover_no_rljoin1", discover_body(2, ORG_HINT), "RLJOIN1 is required")
    dbad("zt_discover_unknown_profile", discover_body(5, ORG_HINT), "unknown profile bit")
    dbad("zt_discover_avoid_gap", discover_body(1, ORG_HINT, avoid=(0, 7)), "avoid slots pack from the front")
    dbad("zt_discover_avoid_duplicate", discover_body(1, ORG_HINT, avoid=(7, 7)), "avoid slots distinct")
    dbad("zt_discover_preferred_avoided", discover_body(1, ORG_HINT, 7, (7, 0)),
         "the preferred site cannot also be avoided")
    dbad("zt_discover_network_hint", good_body, "DISCOVER carries network_hint 0", network_hint=1)
    dbad("zt_discover_claimed_zero", good_body, "claimed node must be valid", claimed=0)
    dbad("zt_discover_claimed_all_ones", good_body, "claimed node must be valid", claimed=(1 << 64) - 1)
    dbad("zt_discover_capability", good_body, "capability bits are 0 on this lane", capability=1)
    dbad("zt_discover_short", good_body[:-1], "24 B exactly")
    dbad("zt_discover_long", good_body + b"\x00", "24 B exactly")
    dbad("zt_discover_as_offer", good_body, "a DISCOVER body in an OFFER frame",
         kind=KIND["offer"], network_hint=NETWORK_LOW32)


def invalid_offer() -> None:
    ck, rn = bytes(16), bytes(range(16))
    good_body = offer_body(0, 1, ck, rn, ORG_HINT, SITE_HINT, 1, 0)

    def obad(name, body, note, **header):
        h = dict(network_hint=NETWORK_LOW32, claimed=PROXY, capability=0)
        h.update(header)
        frame = rld1(KIND["offer"], h["network_hint"], h["claimed"], NONCE, body, h["capability"])
        bad(name, "zt_offer_frame", frame, note)

    obad("zt_offer_unknown_flag", offer_body(0, 4, ck, rn, ORG_HINT, SITE_HINT, 1, 0), "flags bit2")
    obad("zt_offer_reserved", offer_body(0, 1, ck, rn, ORG_HINT, SITE_HINT, 1, 0, reserved=1),
         "reserved u16 must be 0")
    obad("zt_offer_version_1", offer_body(0, 1, ck, rn, ORG_HINT, SITE_HINT, 1, 0, version=1),
         "body version 3 only")
    obad("zt_offer_class_2", offer_body(0, 1, ck, rn, ORG_HINT, SITE_HINT, 1, 0, cls=2), "class 3 only")
    obad("zt_offer_network_zero", good_body, "OFFER names the site network_low32", network_hint=0)
    obad("zt_offer_claimed_zero", good_body, "claimed proxy must be valid", claimed=0)
    obad("zt_offer_capability", good_body, "capability bits are 0 on this lane", capability=4)
    obad("zt_offer_short", good_body[:-1], "48 B exactly")
    obad("zt_offer_long", good_body + b"\x00", "48 B exactly")


def invalid_objects() -> None:
    ck = bytes(16)
    m = b"\x01\x02\x03"

    def jbad(name, obj, note):
        bad(name, "join_object", obj, note)

    jbad("join_object_phase_3", join_object(3, 1, m), "phases 1-3 are the dev-PSK exchange")
    jbad("join_object_phase_7", join_object(7, 1, m), "unknown phase")
    jbad("join_object_step_0", join_object(EDHOC, 0, m), "EDHOC steps 1..5")
    jbad("join_object_step_6", join_object(EDHOC, 6, m), "EDHOC steps 1..5")
    jbad("join_object_resume_step_4", join_object(RESUME, 4, m), "RLRES1 steps 1..3")
    jbad("join_object_version_2", join_object(EDHOC, 2, m, version=2), "BA prefix version 1")
    jbad("join_object_prefix_reserved", join_object(EDHOC, 2, m, reserved=1), "prefix reserved 0")
    jbad("join_object_m1_without_cookie", join_object(EDHOC, 1, m), "m1 carries the cookie")
    jbad("join_object_m2_with_cookie", join_object(EDHOC, 2, m, ck), "only step 1 carries a cookie")
    jbad("join_object_r2_with_cookie", join_object(RESUME, 2, m, ck), "only step 1 carries a cookie")
    jbad("join_object_cookie_flag_2", join_object(EDHOC, 2, m, flag=2), "cookie flag is 0/1")
    jbad("join_object_head_reserved", join_object(EDHOC, 2, m, head_reserved=1), "head reserved 0")
    jbad("join_object_empty_message", join_object(EDHOC, 2, b""), "a message is 1..960 B")
    jbad("join_object_message_961", join_object(EDHOC, 2, filler("big", 961)), "960 B message ceiling")
    jbad("join_object_truncated_cookie", join_object(EDHOC, 1, b"", flag=1) + bytes(10),
         "the cookie is 16 B")
    jbad("join_object_prefix_only", join_object(EDHOC, 2)[:4], "phase 4 needs its 2 B head")
    jbad("join_object_relay_status_code_0", relay_status_object(0, 0), "status 1..4")
    jbad("join_object_relay_status_code_5", relay_status_object(5, 0), "status 1..4")
    jbad("join_object_relay_status_retry", relay_status_object(BUSY, RETRY_MAX + 1), "retry <= 600000 ms")
    jbad("join_object_relay_status_step_2", relay_status_object(BUSY, 0, step=2), "RelayStatus step 1")
    jbad("join_object_relay_status_long", relay_status_object(BUSY, 0) + b"\x00", "9 B exactly")


def invalid_chunks() -> None:
    ident = 0x10111213
    data106 = bytes(106)

    def cbad(name, payload, carrier, note):
        bad(name, "join_chunk", payload, note, carrier=carrier)

    cbad("join_chunk_small_total", chunk(EDHOC, 2, ident, 0, 116, data106), "rld1",
         "an object that fits one frame is never chunked")
    cbad("join_chunk_wire_small_total", chunk(EDHOC, 2, ident, 0, 128, bytes(118)), "wire",
         "an object that fits one Wire payload is never chunked")
    cbad("join_chunk_total_1025", chunk(EDHOC, 2, ident, 0, 1025, data106), "rld1", "1024 B ceiling")
    cbad("join_chunk_off_grid", chunk(EDHOC, 2, ident, 100, 300, data106), "rld1", "offsets on the 106 B grid")
    cbad("join_chunk_short_data", chunk(EDHOC, 2, ident, 0, 300, bytes(105)), "rld1", "full grid chunk")
    cbad("join_chunk_last_long", chunk(EDHOC, 2, ident, 212, 300, bytes(90)), "rld1",
         "the last chunk is total - offset")
    cbad("join_chunk_offset_past_total", chunk(EDHOC, 2, ident, 318, 300, bytes(1)), "rld1",
         "offset < total")
    cbad("join_chunk_sub_step_6", chunk(EDHOC, 2, ident, 0, 300, data106, sub_override=0x46), "rld1",
         "EDHOC steps 1..5")
    cbad("join_chunk_sub_relay_status", chunk(EDHOC, 2, ident, 0, 300, data106, sub_override=0x61),
         "rld1", "a RelayStatus is never chunked")
    cbad("join_chunk_sub_legacy", chunk(EDHOC, 2, ident, 0, 300, data106, sub_override=0x01), "rld1",
         "sub 1 is the dev-PSK chunk")
    cbad("join_chunk_id_zero", chunk(EDHOC, 2, 0, 0, 300, data106), "rld1", "id nonzero")
    cbad("join_chunk_version_2", chunk(EDHOC, 2, ident, 0, 300, data106, version=2), "rld1", "version 1")
    cbad("join_chunk_header_only", chunk(EDHOC, 2, ident, 0, 300, b""), "rld1", "data required")
    cbad("join_chunk_rld1_oversize", chunk(EDHOC, 2, ident, 0, 300, bytes(118)), "rld1",
         "118 B data is the Wire grid, not RLD1")

    def rbad(name, payload, note):
        bad(name, "join_reply", payload, note)

    rbad("join_reply_short", reply(EDHOC, 2, ident, 10, 0)[:-1], "10 B exactly")
    rbad("join_reply_long", reply(EDHOC, 2, ident, 10, 0) + b"\x00", "10 B exactly")
    rbad("join_reply_reserved", reply(EDHOC, 2, ident, 10, 0, reserved=1), "reserved 0")
    rbad("join_reply_status_3", reply(EDHOC, 2, ident, 10, 3), "status 0..2")
    rbad("join_reply_aborted_received", reply(EDHOC, 2, ident, 10, 2), "an abort carries 0")
    rbad("join_reply_complete_zero", reply(EDHOC, 2, ident, 0, 1), "complete names the total")
    rbad("join_reply_received_1025", reply(EDHOC, 2, ident, 1025, 0), "1024 B ceiling")
    rbad("join_reply_id_zero", reply(EDHOC, 2, 0, 10, 0), "id nonzero")
    rbad("join_reply_version_2", reply(EDHOC, 2, ident, 10, 0, version=2), "version 1")


def invalid_relay() -> None:
    rid, msg = 0x7E57AB1E, filler("m", 40)

    def rb(name, obj, note):
        bad(name, "relay_object", obj, note)

    def h(direction=UP, relay_id=rid, proxy=PROXY, mac=DEVICE_MAC, step=1, state=CONTINUE,
          rssi=-70, phase=EDHOC, version=1):
        return relay_header(direction, relay_id, proxy, mac, step, state, rssi, phase, version)

    rb("relay_dir_0", h(direction=0) + msg, "dir 1 up / 2 down")
    rb("relay_dir_3", h(direction=3) + msg, "dir 1 up / 2 down")
    # NOTE (#116): the old relay_version_2 case (a 24 B head with ver 2)
    # reparses as a valid v2 object; version misuse is covered by the
    # join-relay-v2 invalid vectors instead.
    rb("relay_id_zero", h(relay_id=0) + msg, "relay_id nonzero")
    rb("relay_proxy_zero", h(proxy=0) + msg, "proxy NodeId valid")
    rb("relay_proxy_all_ones", h(proxy=(1 << 64) - 1) + msg, "proxy NodeId valid")
    rb("relay_mac_zero", h(mac=bytes(6)) + msg, "joiner MAC unicast")
    rb("relay_mac_multicast", h(mac=bytes.fromhex("010000001234")) + msg, "joiner MAC unicast")
    rb("relay_phase_6", h(phase=6) + msg, "phase 4 or 5")
    rb("relay_phase_3", h(phase=3) + msg, "phase 4 or 5")
    rb("relay_step_6", h(step=6) + msg, "EDHOC steps 1..5")
    rb("relay_resume_step_4", h(step=4, phase=RESUME) + msg, "RLRES1 steps 1..3")
    rb("relay_state_3", h(state=3) + msg, "state 0..2")
    rb("relay_up_final", h(state=FINAL, step=3) + msg, "only a down object is final")
    rb("relay_up_step_2", h(step=2) + msg, "m2 flows down")
    rb("relay_down_continue_step_4", h(DOWN, step=4, rssi=0) + msg, "m4 is final")
    rb("relay_down_continue_step_3", h(DOWN, step=3, rssi=0) + msg, "m3 flows up")
    rb("relay_down_final_step_2", h(DOWN, step=2, state=FINAL, rssi=0) + msg, "EDHOC final is 4/5")
    rb("relay_up_rssi_positive", h(rssi=5) + msg, "RSSI <= 0 dBm")
    rb("relay_down_rssi", h(DOWN, step=2, rssi=-40) + msg, "down objects carry RSSI 0")
    rb("relay_empty_message", h(), "a message is 1..960 B")
    rb("relay_message_961", h() + filler("big", 961), "960 B message ceiling")
    rb("relay_abort_body_4", h(state=ABORT) + u8(ABORTED) + u8(0) * 3, "abort body 5 B")
    rb("relay_abort_body_6", h(state=ABORT) + u8(ABORTED) + u32(0) + u8(0), "abort body 5 B")
    rb("relay_up_abort_busy", h(state=ABORT) + u8(BUSY) + u32(0), "a proxy abort is Aborted")
    rb("relay_down_abort_queued", h(DOWN, state=ABORT, rssi=0) + u8(QUEUED) + u32(0),
       "Queued is not an abort")
    rb("relay_abort_retry", h(DOWN, state=ABORT, rssi=0) + u8(BUSY) + u32(RETRY_MAX + 1),
       "retry <= 600000 ms")
    rb("relay_abort_status_0", h(DOWN, state=ABORT, rssi=0) + u8(0) + u32(0), "status 1..4")
    rb("relay_header_only_short", h()[:-1], "24 B header")

    def sbad(name, obj, wire_type, note):
        bad(name, "relay_single_frame", obj, note, wire_type=wire_type)

    sbad("relay_single_final_on_type_3",
         relay_object(DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 4, FINAL, 0, msg), 3,
         "a final down object rides type 4")
    sbad("relay_single_up_on_type_4",
         relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -70, msg), 4,
         "up objects ride type 3")
    sbad("relay_single_continue_on_type_4",
         relay_object(DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 2, CONTINUE, 0, msg), 4,
         "a continuing down object rides type 3")
    sbad("relay_single_oversize",
         relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -70, filler("o", 105)), 3,
         "129 B does not fit one Wire payload")


def main() -> None:
    base.self_test()
    for sub_dir in ("valid", "invalid"):
        shutil.rmtree(OUT / sub_dir, ignore_errors=True)
        (OUT / sub_dir).mkdir(parents=True)
    # The corpus is shared with the v2 generator (#116): manage only the
    # files owned here, never the whole directory.
    CORPUS.mkdir(parents=True, exist_ok=True)

    discovery_frames = valid_discovery()
    valid_cookies()
    valid_objects()
    rld1_frames = valid_rld1_sequences()
    valid_chunk_codecs()
    invalid_discovery()
    invalid_offer()
    invalid_objects()
    invalid_chunks()
    invalid_relay()

    # Engine script for fuzz_sdkv1_join: [u16 len | RLD1 frame]... of a
    # complete exchange (the Wire script moved to the v2 generator).
    seeds.append(("script.rld1_exchange", u8(0) + script(discovery_frames + rld1_frames)))
    for name, data in seeds:
        (CORPUS / name).write_bytes(data)
    print(f"join-transport: {counts['valid']} valid, {counts['invalid']} invalid, "
          f"{len(seeds)} fuzz seeds")


if __name__ == "__main__":
    main()
