#!/usr/bin/env python3
"""Independent golden vectors for the Wire relay lane v2 (#116).

Covers sdkv1 §7.1 (the 32 B RelayHeader + message between proxy and gateway,
with both service epochs), the 18 B Wire chunks/replies, the 24 B gateway
epoch query/reply, and the HostOps 0x60-0x63 join relay family (schema 2).

Like tools/gen_sdkv1_join_transport_vectors.py this generator is standalone:
only the Python standard library, no calls into C++ or Rust. The C++ checks
(tests/cpp/test_sdkv1_join_transport.cpp, tests/cpp/test_usb.cpp) and the
Rust checks (host/routeloom-protocol/tests/join_relay_golden.rs) consume the
same fixtures; every valid vector must decode to the listed fields and
re-encode byte-for-byte, every invalid one must be refused.

Outputs (flattened `--out` roots the tree; default is the repo):
  protocol/sdkv1-golden/join-relay-v2/{valid,invalid}/*.json + manifest.json
  protocol/usb-golden/join-relay-v2/{valid,invalid}/*.json + manifest.json
  tests/fuzz/corpus/sdkv1_join/script.wire_exchange_v2 + per-vector seeds

Usage:
  python3 tools/gen_sdkv1_join_relay_v2_vectors.py [--out DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def u8(v: int) -> bytes: return struct.pack(">B", v)
def i8(v: int) -> bytes: return struct.pack(">b", v)
def u16(v: int) -> bytes: return struct.pack(">H", v)
def u32(v: int) -> bytes: return struct.pack(">I", v)
def u64(v: int) -> bytes: return struct.pack(">Q", v)


# --- constants of the design as resolved for #116 --------------------------------------
WIRE_MAX_PAYLOAD = 128
OBJECT_MAX, MESSAGE_MAX = 1024, 960
RELAY_VERSION, RELAY_HEAD = 2, 32
RELAY_OBJECT_MAX = RELAY_HEAD + MESSAGE_MAX  # 992
ABORT_BODY = 5
CHUNK_VERSION, CHUNK_HEAD, CHUNK_GRID = 2, 18, WIRE_MAX_PAYLOAD - 18  # 110
REPLY_SIZE = 18
QUERY_KIND, REPLY_KIND, QUERY_SIZE = 3, 4, 24
READY_BIT = 0x01
KIND = {"auth": 3, "result": 4, "chunk": 5, "reply": 6}
EDHOC, RESUME = 4, 5
UP, DOWN = 1, 2
CONTINUE, FINAL, ABORT = 0, 1, 2
QUEUED, UNREACHABLE, BUSY, ABORTED = 1, 2, 3, 4
RETRY_MAX = 600000
U32MAX = 0xFFFFFFFF

# USB join relay family v2 (#116 section 5.2).
USB_SCHEMA, SUB_UP, SUB_DOWN, SUB_ABORT, SUB_RESULT = 2, 0x60, 0x61, 0x62, 0x63
UP_FIXED, DOWN_FIXED, ABORT_PAYLOAD, RESULT_PAYLOAD = 17, 8, 21, 22
HOPS_MAX = 254
# ConfigOpsResult values shared with the result codec (usb_host_ops.hpp:
# Ok = 0, Busy = 1, Denied = 3, Unsupported = 4, Invalid = 5,
# Indeterminate = 7, NoRoute = 8).
RESULT = {"Ok": 0, "Busy": 1, "Denied": 3, "Unsupported": 4, "Invalid": 5,
          "Indeterminate": 7, "NoRoute": 8}
# RelayAbortReason values shared with the abort codec.
ABORT_REASON = {"proxy_aborted": 1, "gateway_expired": 2, "delivery_failed": 3,
                "host_aborted": 4, "superseded": 5}

# Test identities (TEST MATERIAL): the same site/nodes as the v1 vectors.
DEVICE = 0x00A1000000001234
DEVICE_MAC = bytes.fromhex("020000001234")
PROXY = 0x00A1000000000777
GATEWAY = 0x00A1000000000001
GW_EPOCH, PX_EPOCH = 7, 3
QUERY_NONCE = bytes(range(0x40, 0x50))
QUERY_NONCE_2 = bytes(range(0x80, 0x90))

FMT_WIRE = "routeloom-sdkv1-join-relay-v2-golden-v1"
FMT_USB = "routeloom-usb-join-relay-v2-golden-v1"


def filler(label: str, size: int) -> bytes:
    """Deterministic opaque message bytes (never parsed by the transport)."""
    out, counter = b"", 0
    while len(out) < size:
        out += hashlib.sha256(f"RouteLoom/join-relay-v2/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:size]


# --- encoders straight from the layouts -------------------------------------------------
def sub(phase: int, step: int) -> int:
    return (phase << 4) | step


def chunk2(phase: int, step: int, ident: int, offset: int, total: int, data: bytes,
           gw_epoch: int = GW_EPOCH, px_epoch: int = PX_EPOCH, version: int = 2,
           sub_override: int | None = None) -> bytes:
    s = sub(phase, step) if sub_override is None else sub_override
    return (u8(version) + u8(s) + u32(ident) + u16(offset) + u16(total) +
            u32(gw_epoch) + u32(px_epoch) + data)


def reply2(phase: int, step: int, ident: int, received: int, status: int,
           gw_epoch: int = GW_EPOCH, px_epoch: int = PX_EPOCH, reserved: int = 0,
           version: int = 2) -> bytes:
    return (u8(version) + u8(sub(phase, step)) + u32(ident) + u16(received) +
            u8(status) + u8(reserved) + u32(gw_epoch) + u32(px_epoch))


def chunks_of(obj: bytes, phase: int, step: int, ident: int,
              gw_epoch: int = GW_EPOCH, px_epoch: int = PX_EPOCH) -> list[bytes]:
    assert WIRE_MAX_PAYLOAD < len(obj) <= OBJECT_MAX
    return [chunk2(phase, step, ident, off, len(obj), obj[off:off + CHUNK_GRID],
                   gw_epoch, px_epoch)
            for off in range(0, len(obj), CHUNK_GRID)]


def relay_header(direction: int, relay_id: int, proxy: int, mac: bytes, step: int,
                 state: int, rssi: int, phase: int, gw_epoch: int = GW_EPOCH,
                 px_epoch: int = PX_EPOCH, version: int = 2) -> bytes:
    return (u8(version) + u8(direction) + u32(relay_id) + u64(proxy) + mac +
            u8(step) + u8(state) + i8(rssi) + u8(phase) +
            u32(gw_epoch) + u32(px_epoch))


def relay_object(direction, relay_id, proxy, mac, phase, step, state, rssi,
                 message=b"", abort=None, gw_epoch=GW_EPOCH,
                 px_epoch=PX_EPOCH) -> bytes:
    body = message if abort is None else u8(abort[0]) + u32(abort[1])
    return relay_header(direction, relay_id, proxy, mac, step, state, rssi,
                        phase, gw_epoch, px_epoch) + body


def single_type(direction: int, state: int) -> int:
    return KIND["result"] if direction == DOWN and state != CONTINUE else KIND["auth"]


def epoch_query(nonce: bytes = QUERY_NONCE, version: int = 2, kind: int = QUERY_KIND,
                flags: int = 0, reserved: int = 0, fixed: int = 0) -> bytes:
    return u8(version) + u8(kind) + u8(flags) + u8(reserved) + u32(fixed) + nonce


def epoch_reply(gw_epoch: int, nonce: bytes, ready: bool, version: int = 2,
                kind: int = REPLY_KIND, flags: int | None = None,
                reserved: int = 0) -> bytes:
    fl = (READY_BIT if ready else 0) if flags is None else flags
    return u8(version) + u8(kind) + u8(fl) + u8(reserved) + u32(gw_epoch) + nonce


def usb_inner(subcode: int, payload: bytes, schema: int = USB_SCHEMA) -> bytes:
    return u8(schema) + u8(subcode) + u16(len(payload)) + payload


def usb_up(gateway: int, from_proxy: int, hops: int, obj: bytes) -> bytes:
    return usb_inner(SUB_UP, u64(gateway) + u64(from_proxy) + u8(hops) + obj)


def usb_down(to_proxy: int, obj: bytes) -> bytes:
    return usb_inner(SUB_DOWN, u64(to_proxy) + obj)


def usb_abort(proxy: int, relay_id: int, gw_epoch: int, px_epoch: int,
              reason: int) -> bytes:
    return usb_inner(SUB_ABORT,
                     u64(proxy) + u32(relay_id) + u32(gw_epoch) + u32(px_epoch) + u8(reason))


def usb_result(result: int, proxy: int, relay_id: int, gw_epoch: int,
               px_epoch: int) -> bytes:
    return usb_inner(SUB_RESULT,
                     u16(result) + u64(proxy) + u32(relay_id) + u32(gw_epoch) + u32(px_epoch))


# --- emit -----------------------------------------------------------------------------------
class Sink:
    def __init__(self) -> None:
        self.counts = {"valid": 0, "invalid": 0}
        self.seeds: list[tuple[str, bytes]] = []
        self.files: list[str] = []

    def emit(self, out: Path, folder: str, name: str, record: dict, fmt: str) -> None:
        record = dict(record, format=fmt, name=name)
        path = out / folder / f"{name}.json"
        assert not path.exists(), name
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        self.counts[folder] += 1
        self.files.append(f"{folder}/{name}.json")

    def good(self, out: Path, name: str, codec: str, record: dict, fmt: str,
             *seed_bytes: bytes) -> None:
        self.emit(out, "valid", name, dict(record, codec=codec, expect="ok"),
                  fmt)
        for i, data in enumerate(seed_bytes):
            self.seeds.append((f"{name}.{i}", data))

    def bad(self, out: Path, name: str, codec: str, encoded: bytes, note: str,
            fmt: str, **extra) -> None:
        record = dict(codec=codec, encoded_hex=encoded.hex(), expect="error",
                      note=note)
        record.update(extra)
        self.emit(out, "invalid", name, record, fmt)


WIRE: Sink
USB: Sink
OUT_WIRE: Path
OUT_USB: Path
CORPUS: Path


def relay_record(obj: bytes, direction, relay_id, proxy, mac, phase, step,
                 state, rssi, gw_epoch, px_epoch, message=b"",
                 abort=(0, 0)) -> dict:
    return dict(object_hex=obj.hex(), dir=direction, relay_id=relay_id,
                proxy=proxy, joiner_mac_hex=mac.hex(), phase=phase, step=step,
                state=state, rssi_u8=rssi & 0xFF, gateway_epoch=gw_epoch,
                proxy_epoch=px_epoch, message_hex=message.hex(),
                abort_status=abort[0], abort_retry_ms=abort[1],
                wire_type=single_type(direction, state)
                if len(obj) <= WIRE_MAX_PAYLOAD else 0)


def valid_relay_objects() -> list[tuple[int, bytes]]:
    rid = 0x7E57AB1E
    wire_script: list[tuple[int, bytes]] = []
    cases = [
        ("relay2_up_m1", UP, EDHOC, 1, CONTINUE, -71, filler("m1", 59), None,
         "m1 up: 91 B, type 3"),
        ("relay2_down_m2", DOWN, EDHOC, 2, CONTINUE, 0, filler("m2", 372), None,
         "m2 down: 404 B, 4 chunks of 110/110/110/74"),
        ("relay2_up_m3", UP, EDHOC, 3, CONTINUE, -64, filler("m3", 404), None,
         "m3 up: 436 B, 4 chunks"),
        ("relay2_down_m4_final", DOWN, EDHOC, 4, FINAL, 0, filler("m4", 353),
         None, "m4 final: 385 B, 4 chunks"),
        ("relay2_down_deny_final", DOWN, EDHOC, 4, FINAL, 0, filler("m4d", 31),
         None, "short m4 (deny) final: type 4 single frame"),
        ("relay2_down_error_final", DOWN, EDHOC, 5, FINAL, 0, filler("err", 3),
         None, "EDHOC error from the authority: final, type 4"),
        ("relay2_up_error", UP, EDHOC, 5, CONTINUE, -80, filler("err", 3),
         None, "device error up"),
        ("relay2_up_r1", UP, RESUME, 1, CONTINUE, -50, filler("r1", 109), None,
         "R1 up: 141 B, 2 chunks"),
        ("relay2_down_r2_final", DOWN, RESUME, 2, FINAL, 0, filler("r2", 52),
         None, "R2 final"),
        ("relay2_down_r2_continue", DOWN, RESUME, 2, CONTINUE, 0, filler("r2c", 52),
         None, "R2 continue: R3 follows"),
        ("relay2_up_r3", UP, RESUME, 3, CONTINUE, -55, filler("r3", 20), None,
         "R3 up: single frame"),
        ("relay2_down_busy_abort", DOWN, EDHOC, 1, ABORT, 0, b"",
         (BUSY, 2000), "authority busy before m2: abort, type 4"),
        ("relay2_down_unreachable_abort", DOWN, EDHOC, 3, ABORT, 0, b"",
         (UNREACHABLE, 5000), "gateway has no host: abort"),
        ("relay2_up_abort", UP, EDHOC, 3, ABORT, -60, b"", (ABORTED, 0),
         "proxy ends the relay (device silent)"),
        ("relay2_up_max", UP, EDHOC, 1, CONTINUE, -127,
         filler("max", MESSAGE_MAX), None, "largest relay object: 992 B"),
        ("relay2_single_128", UP, EDHOC, 1, CONTINUE, -70, filler("b128", 96),
         None, "single-frame boundary: 128 B rides one frame"),
        ("relay2_chunked_129", UP, EDHOC, 1, CONTINUE, -70, filler("b129", 97),
         None, "chunk boundary: 129 B rides 2 chunks (110+19)"),
    ]
    for name, direction, phase, step, state, rssi, message, abort, note in cases:
        obj = relay_object(direction, rid, PROXY, DEVICE_MAC, phase, step,
                           state, rssi, message, abort)
        record = relay_record(obj, direction, rid, PROXY, DEVICE_MAC, phase,
                              step, state, rssi, GW_EPOCH, PX_EPOCH, message,
                              abort or (0, 0))
        record["note"] = note
        frames = []
        if len(obj) <= WIRE_MAX_PAYLOAD:
            frames.append((single_type(direction, state), obj))
        else:
            for part in chunks_of(obj, phase, step, rid):
                frames.append((KIND["chunk"], part))
        record["frame_count"] = len(frames)
        for i, (ftype, payload) in enumerate(frames):
            record[f"frame_{i:02d}_type"] = ftype
            record[f"frame_{i:02d}_hex"] = payload.hex()
        if len(frames) > 1:
            received = 0
            for i, (_, payload) in enumerate(frames):
                received += len(payload) - CHUNK_HEAD
                record[f"receipt_{i:02d}_hex"] = reply2(
                    phase, step, rid, received,
                    1 if received == len(obj) else 0).hex()
        WIRE.good(OUT_WIRE, name, "relay_object", record, FMT_WIRE, obj)
        if name in ("relay2_up_m1", "relay2_down_m2", "relay2_up_m3",
                    "relay2_down_m4_final"):
            wire_script += frames
    # Epoch/id corners: the same m1 shape with extreme tokens.
    for name, gw, px, ident, note in (
            ("relay2_epoch_min", 1, 1, rid, "epochs 1/1 are the smallest live tokens"),
            ("relay2_epoch_max", U32MAX, U32MAX, rid, "epochs MAX/MAX compare, never wrap"),
            ("relay2_epoch_mixed", 1, U32MAX, rid, "independent epoch lanes"),
            ("relay2_id_max", GW_EPOCH, PX_EPOCH, U32MAX,
             "relay_id MAX is usable exactly once"),
            ("relay2_id_max_pred", GW_EPOCH, PX_EPOCH, U32MAX - 1,
             "relay_id MAX-1 precedes MAX")):
        obj = relay_object(UP, ident, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE,
                           -71, filler("m1", 59), None, gw, px)
        record = relay_record(obj, UP, ident, PROXY, DEVICE_MAC, EDHOC, 1,
                              CONTINUE, -71, gw, px, filler("m1", 59))
        record["note"] = note
        record["frame_count"] = 1
        record["frame_00_type"] = KIND["auth"]
        record["frame_00_hex"] = obj.hex()
        WIRE.good(OUT_WIRE, name, "relay_object", record, FMT_WIRE, obj)
    return wire_script


def valid_chunks_replies() -> None:
    rid = 0x7E57AB1E
    m2 = relay_object(DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 2, CONTINUE, 0,
                      filler("m2", 372))
    for i, part in enumerate(chunks_of(m2, EDHOC, 2, rid)):
        WIRE.good(OUT_WIRE, f"relay2_chunk_m2_{i}", "join_chunk",
                  dict(payload_hex=part.hex(), carrier="wire", phase=EDHOC,
                       step=2, id=rid, offset=i * CHUNK_GRID, total=len(m2),
                       gateway_epoch=GW_EPOCH, proxy_epoch=PX_EPOCH,
                       data_hex=part[CHUNK_HEAD:].hex(), note="grid 110 B"),
                  FMT_WIRE, part)
    edge = relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -70,
                        filler("b129", 97))
    for i, part in enumerate(chunks_of(edge, EDHOC, 1, rid)):
        WIRE.good(OUT_WIRE, f"relay2_chunk_129_{i}", "join_chunk",
                  dict(payload_hex=part.hex(), carrier="wire", phase=EDHOC,
                       step=1, id=rid, offset=i * CHUNK_GRID, total=len(edge),
                       gateway_epoch=GW_EPOCH, proxy_epoch=PX_EPOCH,
                       data_hex=part[CHUNK_HEAD:].hex(),
                       note="129 B object: 110 + 19"), FMT_WIRE, part)
    big = relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -127,
                       filler("max", MESSAGE_MAX))
    parts = chunks_of(big, EDHOC, 1, rid)
    assert len(parts) == 10, len(parts)
    for i in (0, 9):
        WIRE.good(OUT_WIRE, f"relay2_chunk_max_{i}", "join_chunk",
                  dict(payload_hex=parts[i].hex(), carrier="wire", phase=EDHOC,
                       step=1, id=rid, offset=i * CHUNK_GRID, total=len(big),
                       gateway_epoch=GW_EPOCH, proxy_epoch=PX_EPOCH,
                       data_hex=parts[i][CHUNK_HEAD:].hex(),
                       note="992 B object: first/last of 10 chunks"),
                  FMT_WIRE, parts[i])
    for name, phase, step, ident, received, status, note in (
            ("relay2_reply_progress", EDHOC, 2, rid, 110, 0,
             "18 B wire reply"),
            ("relay2_reply_complete", EDHOC, 2, rid, len(m2), 1,
             "complete names the total"),
            ("relay2_reply_aborted", EDHOC, 2, rid, 0, 2,
             "an abort carries 0")):
        payload = reply2(phase, step, ident, received, status)
        WIRE.good(OUT_WIRE, name, "join_reply",
                  dict(payload_hex=payload.hex(), carrier="wire", phase=phase,
                       step=step, id=ident, received=received, status=status,
                       gateway_epoch=GW_EPOCH, proxy_epoch=PX_EPOCH, note=note),
                  FMT_WIRE, payload)


def valid_epoch() -> list[tuple[int, bytes]]:
    q = epoch_query(QUERY_NONCE)
    WIRE.good(OUT_WIRE, "relay2_epoch_query", "epoch_query",
              dict(payload_hex=q.hex(), nonce_hex=QUERY_NONCE.hex(),
                   note="proxy asks for the gateway epoch"), FMT_WIRE, q)
    q2 = epoch_query(QUERY_NONCE_2)
    WIRE.good(OUT_WIRE, "relay2_epoch_query_2", "epoch_query",
              dict(payload_hex=q2.hex(), nonce_hex=QUERY_NONCE_2.hex(),
                   note="a second fresh nonce"), FMT_WIRE, q2)
    for name, epoch, nonce, ready, note in (
            ("relay2_epoch_reply_ready", GW_EPOCH, QUERY_NONCE, True,
             "gateway answers, authority ready"),
            ("relay2_epoch_reply_not_ready", GW_EPOCH, QUERY_NONCE_2, False,
             "gateway answers, no host attached"),
            ("relay2_epoch_reply_max", U32MAX, QUERY_NONCE, True,
             "epoch MAX is a live epoch")):
        payload = epoch_reply(epoch, nonce, ready)
        WIRE.good(OUT_WIRE, name, "epoch_reply",
                  dict(payload_hex=payload.hex(), gateway_epoch=epoch,
                       nonce_hex=nonce.hex(), ready=1 if ready else 0,
                       note=note), FMT_WIRE, payload)
    return [(KIND["auth"], q), (KIND["auth"], epoch_reply(GW_EPOCH, QUERY_NONCE, True))]


def invalid_wire() -> None:
    rid, msg = 0x7E57AB1E, filler("m", 40)

    def rb(name, obj, note):
        WIRE.bad(OUT_WIRE, name, "relay_object", obj, note, FMT_WIRE)

    def h(direction=UP, relay_id=rid, proxy=PROXY, mac=DEVICE_MAC, step=1,
          state=CONTINUE, rssi=-70, phase=EDHOC, gw_epoch=GW_EPOCH,
          px_epoch=PX_EPOCH, version=2):
        return relay_header(direction, relay_id, proxy, mac, step, state,
                            rssi, phase, gw_epoch, px_epoch, version)

    # v1/v2 mixing: v1 bytes (24 B head, ver 1) and a ver-2 24 B head are
    # both rejected, never upgraded by filling epoch 0.
    v1head = (u8(1) + u8(UP) + u32(rid) + u64(PROXY) + DEVICE_MAC + u8(1) +
              u8(CONTINUE) + i8(-70) + u8(EDHOC))
    rb("relay2_v1_object", v1head + msg, "a v1 object is not a v2 object")
    rb("relay2_v1_abort", v1head[:20] + u8(1) + u8(ABORT) + v1head[22:] +
       u8(ABORTED) + u32(0), "a v1 abort is not a v2 object")
    rb("relay2_version_1", h(version=1) + msg, "RelayHeader version 2")
    rb("relay2_version_3", h(version=3) + msg, "RelayHeader version 2")
    rb("relay2_epoch_gw_zero", h(gw_epoch=0) + msg, "gateway epoch nonzero")
    rb("relay2_epoch_px_zero", h(px_epoch=0) + msg, "proxy epoch nonzero")
    rb("relay2_dir_0", h(direction=0) + msg, "dir 1 up / 2 down")
    rb("relay2_dir_3", h(direction=3) + msg, "dir 1 up / 2 down")
    rb("relay2_dir_query_kind", h()[:1] + u8(QUERY_KIND) + h()[2:] + msg,
       "kind 3 is a query, not an object head")
    rb("relay2_id_zero", h(relay_id=0) + msg, "relay_id nonzero")
    rb("relay2_proxy_zero", h(proxy=0) + msg, "proxy NodeId valid")
    rb("relay2_proxy_all_ones", h(proxy=(1 << 64) - 1) + msg,
       "proxy NodeId valid")
    rb("relay2_mac_zero", h(mac=bytes(6)) + msg, "joiner MAC unicast")
    rb("relay2_mac_multicast", h(mac=bytes.fromhex("010000001234")) + msg,
       "joiner MAC unicast")
    rb("relay2_phase_6", h(phase=6) + msg, "phase 4 or 5")
    rb("relay2_phase_3", h(phase=3) + msg, "phase 4 or 5")
    rb("relay2_step_6", h(step=6) + msg, "EDHOC steps 1..5")
    rb("relay2_resume_step_4", h(step=4, phase=RESUME) + msg,
       "RLRES1 steps 1..3")
    rb("relay2_state_3", h(state=3) + msg, "state 0..2")
    rb("relay2_up_final", h(state=FINAL, step=3) + msg,
       "only a down object is final")
    rb("relay2_up_step_2", h(step=2) + msg, "m2 flows down")
    rb("relay2_up_step_4", h(step=4) + msg, "m4 flows down")
    rb("relay2_down_continue_step_4", h(DOWN, step=4, rssi=0) + msg,
       "m4 is final")
    rb("relay2_down_continue_step_3", h(DOWN, step=3, rssi=0) + msg,
       "m3 flows up")
    rb("relay2_down_final_step_2", h(DOWN, step=2, state=FINAL, rssi=0) + msg,
       "EDHOC final is 4/5")
    rb("relay2_down_final_step_3", h(DOWN, step=3, state=FINAL, rssi=0) + msg,
       "no final step 3")
    rb("relay2_up_rssi_positive", h(rssi=5) + msg, "RSSI <= 0 dBm")
    rb("relay2_down_rssi", h(DOWN, step=2, rssi=-40) + msg,
       "down objects carry RSSI 0")
    rb("relay2_empty_message", h(), "a message is 1..960 B")
    rb("relay2_header_only_short", h()[:-1], "32 B header")
    rb("relay2_message_961", h() + filler("big", 961), "960 B message ceiling")
    rb("relay2_object_993", h() + filler("big", 961), "992 B object ceiling")
    rb("relay2_abort_trailing", relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1,
                                                ABORT, -70, b"", (ABORTED, 0)) + b"\x00",
       "an abort is exactly 37 B")
    rb("relay2_abort_body_4", h(state=ABORT) + u8(ABORTED) + u8(0) * 3,
       "abort body 5 B")
    rb("relay2_abort_body_6", h(state=ABORT) + u8(ABORTED) + u32(0) + u8(0),
       "abort body 5 B")
    rb("relay2_up_abort_busy", h(state=ABORT) + u8(BUSY) + u32(0),
       "a proxy abort is Aborted")
    rb("relay2_down_abort_queued", h(DOWN, state=ABORT, rssi=0) + u8(QUEUED) +
       u32(0), "Queued is not an abort")
    rb("relay2_abort_retry",
       h(DOWN, state=ABORT, rssi=0) + u8(BUSY) + u32(RETRY_MAX + 1),
       "retry <= 600000 ms")
    rb("relay2_abort_status_0", h(DOWN, state=ABORT, rssi=0) + u8(0) + u32(0),
       "status 1..4")
    rb("relay2_abort_status_5", h(DOWN, state=ABORT, rssi=0) + u8(5) + u32(0),
       "status 1..4")

    def sbad(name, obj, wire_type, note):
        WIRE.bad(OUT_WIRE, name, "relay_single_frame", obj, note, FMT_WIRE,
                 wire_type=wire_type)

    sbad("relay2_single_final_on_type_3",
         relay_object(DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 4, FINAL, 0, msg),
         3, "a final down object rides type 4")
    sbad("relay2_single_up_on_type_4",
         relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -70,
                      msg), 4, "up objects ride type 3")
    sbad("relay2_single_continue_on_type_4",
         relay_object(DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 2, CONTINUE, 0,
                      msg), 4, "a continuing down object rides type 3")
    sbad("relay2_single_oversize",
         relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -70,
                      filler("o", 97)), 3, "129 B does not fit one Wire payload")
    sbad("relay2_single_abort_up_on_type_4",
         relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, ABORT, -70, b"",
                      (ABORTED, 0)), 4, "an up abort rides type 3")

    def cbad(name, payload, note, carrier="wire"):
        WIRE.bad(OUT_WIRE, name, "join_chunk", payload, note, FMT_WIRE,
                 carrier=carrier)

    ident = 0x10111213
    data110 = bytes(110)
    cbad("relay2_chunk_v1_head",
         u8(1) + u8(sub(EDHOC, 2)) + u32(ident) + u16(0) + u16(300) + bytes(106),
         "a v1 chunk is not a v2 chunk")
    cbad("relay2_chunk_gw_zero",
         chunk2(EDHOC, 2, ident, 0, 300, data110, gw_epoch=0),
         "gateway epoch nonzero")
    cbad("relay2_chunk_px_zero",
         chunk2(EDHOC, 2, ident, 0, 300, data110, px_epoch=0),
         "proxy epoch nonzero")
    cbad("relay2_chunk_small_total",
         chunk2(EDHOC, 2, ident, 0, 128, data110),
         "an object that fits one Wire payload is never chunked")
    cbad("relay2_chunk_total_1025",
         chunk2(EDHOC, 2, ident, 0, 1025, data110), "1024 B ceiling")
    cbad("relay2_chunk_off_grid",
         chunk2(EDHOC, 2, ident, 100, 300, data110),
         "offsets on the 110 B grid")
    cbad("relay2_chunk_old_grid",
         chunk2(EDHOC, 2, ident, 118, 300, data110),
         "118 is the v1 grid, not v2")
    cbad("relay2_chunk_short_data",
         chunk2(EDHOC, 2, ident, 0, 300, bytes(109)), "full grid chunk")
    cbad("relay2_chunk_last_long",
         chunk2(EDHOC, 2, ident, 220, 300, bytes(82)),
         "the last chunk is total - offset")
    cbad("relay2_chunk_offset_past_total",
         chunk2(EDHOC, 2, ident, 330, 300, bytes(1)), "offset < total")
    cbad("relay2_chunk_sub_step_6",
         chunk2(EDHOC, 2, ident, 0, 300, data110, sub_override=0x46),
         "EDHOC steps 1..5")
    cbad("relay2_chunk_sub_relay_status",
         chunk2(EDHOC, 2, ident, 0, 300, data110, sub_override=0x61),
         "a RelayStatus is never chunked")
    cbad("relay2_chunk_id_zero", chunk2(EDHOC, 2, 0, 0, 300, data110),
         "id nonzero")
    cbad("relay2_chunk_version_1",
         chunk2(EDHOC, 2, ident, 0, 300, data110, version=1), "wire version 2")
    cbad("relay2_chunk_version_3",
         chunk2(EDHOC, 2, ident, 0, 300, data110, version=3), "wire version 2")
    cbad("relay2_chunk_header_only",
         chunk2(EDHOC, 2, ident, 0, 300, b""), "data required")
    cbad("relay2_chunk_oversize",
         chunk2(EDHOC, 2, ident, 0, 300, bytes(111)),
         "111 B data overflows the Wire payload")
    # RLD1 carries no epochs and the v1 shape: on the wire it is short.
    cbad("relay2_chunk_rld1_shape",
         u8(1) + u8(sub(EDHOC, 2)) + u32(ident) + u16(0) + u16(300) + bytes(106),
         "a 116 B RLD1 chunk is short for wire")

    def rbad(name, payload, note, carrier="wire"):
        WIRE.bad(OUT_WIRE, name, "join_reply", payload, note, FMT_WIRE,
                 carrier=carrier)

    rbad("relay2_reply_v1_size", reply2(EDHOC, 2, ident, 10, 0)[:10],
         "a 10 B v1 reply is short for wire")
    rbad("relay2_reply_long", reply2(EDHOC, 2, ident, 10, 0) + b"\x00",
         "18 B exactly")
    rbad("relay2_reply_reserved",
         reply2(EDHOC, 2, ident, 10, 0, reserved=1), "reserved 0")
    rbad("relay2_reply_status_3", reply2(EDHOC, 2, ident, 10, 3),
         "status 0..2")
    rbad("relay2_reply_aborted_received", reply2(EDHOC, 2, ident, 10, 2),
         "an abort carries 0")
    rbad("relay2_reply_complete_zero", reply2(EDHOC, 2, ident, 0, 1),
         "complete names the total")
    rbad("relay2_reply_received_1025", reply2(EDHOC, 2, ident, 1025, 0),
         "1024 B ceiling")
    rbad("relay2_reply_id_zero", reply2(EDHOC, 2, 0, 10, 0), "id nonzero")
    rbad("relay2_reply_gw_zero",
         reply2(EDHOC, 2, ident, 10, 0, gw_epoch=0), "gateway epoch nonzero")
    rbad("relay2_reply_px_zero",
         reply2(EDHOC, 2, ident, 10, 0, px_epoch=0), "proxy epoch nonzero")
    rbad("relay2_reply_version_1",
         reply2(EDHOC, 2, ident, 10, 0, version=1), "wire version 2")

    def qbad(name, payload, note, codec):
        WIRE.bad(OUT_WIRE, name, codec, payload, note, FMT_WIRE)

    qbad("relay2_query_short", epoch_query()[:-1], "24 B exactly",
         "epoch_query")
    qbad("relay2_query_long", epoch_query() + b"\x00", "24 B exactly",
         "epoch_query")
    qbad("relay2_query_version_1", epoch_query(version=1), "version 2",
         "epoch_query")
    qbad("relay2_query_kind_1", epoch_query(kind=1),
         "kind 3 is a query, 1 is an up head", "epoch_query")
    qbad("relay2_query_kind_4", epoch_query(kind=4),
         "kind 4 is a reply", "epoch_query")
    qbad("relay2_query_flags", epoch_query(flags=1), "query flags are 0",
         "epoch_query")
    qbad("relay2_query_reserved", epoch_query(reserved=1), "reserved 0",
         "epoch_query")
    qbad("relay2_query_fixed", epoch_query(fixed=7), "query u32 is 0",
         "epoch_query")
    qbad("relay2_query_zero_nonce", epoch_query(bytes(16)),
         "the nonce is fresh, never zero", "epoch_query")
    qbad("relay2_ereply_short", epoch_reply(7, QUERY_NONCE, True)[:-1],
         "24 B exactly", "epoch_reply")
    qbad("relay2_ereply_long", epoch_reply(7, QUERY_NONCE, True) + b"\x00",
         "24 B exactly", "epoch_reply")
    qbad("relay2_ereply_version_1", epoch_reply(7, QUERY_NONCE, True, version=1),
         "version 2", "epoch_reply")
    qbad("relay2_ereply_kind_3", epoch_reply(7, QUERY_NONCE, True, kind=3),
         "kind 3 is a query", "epoch_reply")
    qbad("relay2_ereply_flags",
         epoch_reply(7, QUERY_NONCE, True, flags=0x02), "only bit0 is defined",
         "epoch_reply")
    qbad("relay2_ereply_reserved",
         epoch_reply(7, QUERY_NONCE, True, reserved=1), "reserved 0",
         "epoch_reply")
    qbad("relay2_ereply_epoch_zero",
         epoch_reply(0, QUERY_NONCE, True), "gateway epoch nonzero",
         "epoch_reply")
    qbad("relay2_ereply_zero_nonce", epoch_reply(7, bytes(16), True),
         "the nonce echo is never zero", "epoch_reply")


def valid_usb() -> None:
    rid = 0x7E57AB1E
    m1 = relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -71,
                      filler("m1", 59))
    m2 = relay_object(DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 2, CONTINUE, 0,
                      filler("m2", 372))
    own = relay_object(UP, 0x0B1E, GATEWAY, DEVICE_MAC, EDHOC, 1, CONTINUE,
                       -60, filler("own", 40))
    for name, inner, record in (
            ("usb2_up_m1", usb_up(GATEWAY, PROXY, 3, m1),
             dict(gateway=GATEWAY, from_proxy=PROXY, hops=3,
                  object_hex=m1.hex(),
                  note="m1 up from proxy 2, three hops away")),
            ("usb2_up_own_join", usb_up(GATEWAY, GATEWAY, 0, own),
             dict(gateway=GATEWAY, from_proxy=GATEWAY, hops=0,
                  object_hex=own.hex(),
                  note="the gateway's own join rides hops 0")),
            ("usb2_down_m2", usb_down(PROXY, m2),
             dict(to_proxy=PROXY, object_hex=m2.hex(),
                  note="m2 down toward proxy 2 (chunked on the wire)")),
            ("usb2_down_max", usb_down(PROXY, relay_object(
                DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 2, CONTINUE, 0,
                filler("big", MESSAGE_MAX))),
             dict(to_proxy=PROXY, object_hex=relay_object(
                 DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 2, CONTINUE, 0,
                 filler("big", MESSAGE_MAX)).hex(),
                 note="largest down inner: 8 + 992 B"))):
        codec = ("join_usb_up" if name.startswith("usb2_up_")
                 else "join_usb_down")
        USB.good(OUT_USB, name, codec,
                 dict(inner_hex=inner.hex(), **record), FMT_USB, inner)
    for name, reason, note in (
            ("usb2_abort_proxy", ABORT_REASON["proxy_aborted"],
             "G->H: the proxy ended the relay"),
            ("usb2_abort_expired", ABORT_REASON["gateway_expired"],
             "G->H: the exchange ran past 20 s"),
            ("usb2_abort_failed", ABORT_REASON["delivery_failed"],
             "G->H: the proxy never confirmed a down object"),
            ("usb2_abort_host", ABORT_REASON["host_aborted"],
             "H->G: the Site Authority cancels"),
            ("usb2_abort_superseded", ABORT_REASON["superseded"],
             "G->H: a newer key replaced this relay")):
        inner = usb_abort(PROXY, rid, GW_EPOCH, PX_EPOCH, reason)
        USB.good(OUT_USB, name, "join_usb_abort",
                 dict(inner_hex=inner.hex(), proxy=PROXY, relay_id=rid,
                      gateway_epoch=GW_EPOCH, proxy_epoch=PX_EPOCH,
                      reason=reason, note=note), FMT_USB, inner)
    cases = [
        ("usb2_result_ok", RESULT["Ok"], PROXY, rid, GW_EPOCH, PX_EPOCH,
         "Ok carries the complete token"),
        ("usb2_result_unsupported", RESULT["Unsupported"], PROXY, rid,
         GW_EPOCH, PX_EPOCH, "the family is not attached"),
        ("usb2_result_busy", RESULT["Busy"], PROXY, rid, GW_EPOCH, PX_EPOCH,
         "Busy: retry the request"),
        ("usb2_result_denied", RESULT["Denied"], 0, 0, 0, 0,
         "a malformed request echoes zeroes"),
        ("usb2_result_invalid", RESULT["Invalid"], PROXY, rid, GW_EPOCH,
         PX_EPOCH, "unknown or terminated token"),
        ("usb2_result_noroute", RESULT["NoRoute"], PROXY, rid, GW_EPOCH,
         PX_EPOCH, "the wire port refused"),
        ("usb2_result_indeterminate", RESULT["Indeterminate"], 0, 0, 0, 0,
         "unknown outcome echoes zeroes"),
    ]
    for name, result, proxy, ident, gw, px, note in cases:
        inner = usb_result(result, proxy, ident, gw, px)
        USB.good(OUT_USB, name, "join_usb_result",
                 dict(inner_hex=inner.hex(), result=result, proxy=proxy,
                      relay_id=ident, gateway_epoch=gw, proxy_epoch=px,
                      note=note), FMT_USB, inner)


def invalid_usb() -> None:
    rid = 0x7E57AB1E
    m1 = relay_object(UP, rid, PROXY, DEVICE_MAC, EDHOC, 1, CONTINUE, -71,
                      filler("m1", 59))
    m2 = relay_object(DOWN, rid, PROXY, DEVICE_MAC, EDHOC, 2, CONTINUE, 0,
                      filler("m2", 59))

    def ubad(name, codec, inner, note):
        USB.bad(OUT_USB, name, codec, inner, note, FMT_USB)

    v1up = (u8(1) + u8(SUB_UP) + u16(UP_FIXED + len(m1)) + u64(GATEWAY) +
            u64(PROXY) + u8(3) + m1)
    ubad("usb2_schema_1_up", "join_usb_up", v1up,
         "schema 1 join frames are rejected, never upgraded")
    ubad("usb2_schema_1_down", "join_usb_down",
         u8(1) + u8(SUB_DOWN) + u16(DOWN_FIXED + len(m2)) + u64(PROXY) + m2,
         "schema 1 join frames are rejected, never upgraded")
    ubad("usb2_schema_3_up", "join_usb_up",
         u8(3) + u8(SUB_UP) + u16(UP_FIXED + len(m1)) + u64(GATEWAY) +
         u64(PROXY) + u8(3) + m1, "schema 2 only")
    good_up = usb_up(GATEWAY, PROXY, 3, m1)
    ubad("usb2_sub_mismatch", "join_usb_up",
         u8(USB_SCHEMA) + u8(SUB_DOWN) + good_up[2:],
         "the sub byte names the codec")
    ubad("usb2_len_short", "join_usb_up", good_up[:-1], "exact length")
    ubad("usb2_len_trailing", "join_usb_up", good_up + b"\x00", "exact length")
    bad_len = bytearray(good_up)
    bad_len[2:4] = struct.pack(">H", len(good_up) - 4 - 1)
    ubad("usb2_len_lies", "join_usb_up", bytes(bad_len),
         "payload_len covers the payload")
    ubad("usb2_up_down_object", "join_usb_up", usb_up(GATEWAY, PROXY, 3, m2),
         "an up carries dir = up")
    ubad("usb2_up_proxy_mismatch", "join_usb_up",
         usb_up(GATEWAY, GATEWAY, 1, m1),
         "the object's proxy is the verified origin")
    ubad("usb2_up_hops_255", "join_usb_up", usb_up(GATEWAY, PROXY, 255, m1),
         "hops 1..254, 0 only for the gateway's own join")
    ubad("usb2_up_hops_0_remote", "join_usb_up", usb_up(GATEWAY, PROXY, 0, m1),
         "hops 0 only when from_proxy == gateway")
    ubad("usb2_up_gateway_zero", "join_usb_up", usb_up(0, PROXY, 3, m1),
         "gateway NodeId valid")
    ubad("usb2_up_empty_object", "join_usb_up",
         usb_up(GATEWAY, PROXY, 3, b""), "an object is never empty")
    ubad("usb2_down_up_object", "join_usb_down", usb_down(PROXY, m1),
         "a down carries dir = down")
    ubad("usb2_down_proxy_mismatch", "join_usb_down",
         usb_down(GATEWAY, m2), "the object's proxy is to_proxy")
    ubad("usb2_down_proxy_zero", "join_usb_down", usb_down(0, m2),
         "to_proxy NodeId valid")
    ubad("usb2_abort_gw_zero", "join_usb_abort",
         usb_abort(PROXY, rid, 0, PX_EPOCH, ABORT_REASON["host_aborted"]),
         "gateway epoch nonzero")
    ubad("usb2_abort_px_zero", "join_usb_abort",
         usb_abort(PROXY, rid, GW_EPOCH, 0, ABORT_REASON["host_aborted"]),
         "proxy epoch nonzero")
    ubad("usb2_abort_id_zero", "join_usb_abort",
         usb_abort(PROXY, 0, GW_EPOCH, PX_EPOCH, ABORT_REASON["host_aborted"]),
         "relay_id nonzero")
    ubad("usb2_abort_proxy_zero", "join_usb_abort",
         usb_abort(0, rid, GW_EPOCH, PX_EPOCH, ABORT_REASON["host_aborted"]),
         "proxy NodeId valid")
    ubad("usb2_abort_reason_0", "join_usb_abort",
         usb_abort(PROXY, rid, GW_EPOCH, PX_EPOCH, 0), "reason 1..5")
    ubad("usb2_abort_reason_6", "join_usb_abort",
         usb_abort(PROXY, rid, GW_EPOCH, PX_EPOCH, 6), "reason 1..5")
    ubad("usb2_abort_short", "join_usb_abort",
         usb_abort(PROXY, rid, GW_EPOCH, PX_EPOCH,
                   ABORT_REASON["host_aborted"])[:-1], "21 B payload exactly")
    ubad("usb2_result_unknown", "join_usb_result",
         usb_result(2, PROXY, rid, GW_EPOCH, PX_EPOCH),
         "2 is not a ConfigOpsResult")
    ubad("usb2_result_ok_zero_token", "join_usb_result",
         usb_result(RESULT["Ok"], 0, 0, 0, 0),
         "an Ok always carries the complete token")
    ubad("usb2_result_ok_zero_epoch", "join_usb_result",
         usb_result(RESULT["Ok"], PROXY, rid, 0, PX_EPOCH),
         "an Ok always carries the complete token")
    ubad("usb2_result_short", "join_usb_result",
         usb_result(RESULT["Ok"], PROXY, rid, GW_EPOCH, PX_EPOCH)[:-1],
         "22 B payload exactly")


def write_manifest(out: Path, sink: Sink, fmt: str, note: str) -> None:
    manifest = dict(format=fmt, generator="tools/gen_sdkv1_join_relay_v2_vectors.py",
                    note=note, valid=sink.counts["valid"],
                    invalid=sink.counts["invalid"], files=sorted(sink.files))
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    global WIRE, USB, OUT_WIRE, OUT_USB, CORPUS
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=".",
                    help="repo root the protocol/tests trees hang under")
    args = ap.parse_args()
    root = Path(args.out)
    OUT_WIRE = root / "protocol/sdkv1-golden/join-relay-v2"
    OUT_USB = root / "protocol/usb-golden/join-relay-v2"
    CORPUS = root / "tests/fuzz/corpus/sdkv1_join"
    import shutil
    for folder in ("valid", "invalid"):
        shutil.rmtree(OUT_WIRE / folder, ignore_errors=True)
        (OUT_WIRE / folder).mkdir(parents=True)
        shutil.rmtree(OUT_USB / folder, ignore_errors=True)
        (OUT_USB / folder).mkdir(parents=True)
    CORPUS.mkdir(parents=True, exist_ok=True)
    WIRE, USB = Sink(), Sink()

    wire_script = valid_relay_objects()
    valid_chunks_replies()
    epoch_script = valid_epoch()
    invalid_wire()
    valid_usb()
    invalid_usb()

    # Engine script for fuzz_sdkv1_join: [u16 len | u8 wire type | payload]...
    # of a query plus a complete m1..m4 exchange.
    frames = epoch_script + wire_script
    script = b"".join(u16(len(p) + 1) + u8(t) + p for t, p in frames)
    (CORPUS / "script.wire_exchange_v2").write_bytes(u8(1) + script)
    # Per-vector seeds plus v1-shaped rejection seeds (kept sharp: v1 bytes
    # must traverse the v2 entrances and die there).
    v1head = (u8(1) + u8(UP) + u32(0x7E57AB1E) + u64(PROXY) + DEVICE_MAC +
              u8(1) + u8(CONTINUE) + i8(-70) + u8(EDHOC))
    seeds = list(WIRE.seeds) + list(USB.seeds) + [
        ("v1_reject_object.0", v1head + filler("m", 40)),
        ("v1_reject_chunk.0",
         u8(1) + u8(sub(EDHOC, 2)) + u32(0x10111213) + u16(0) + u16(300) +
         bytes(106)),
        ("v1_reject_reply.0",
         u8(1) + u8(sub(EDHOC, 2)) + u32(0x10111213) + u16(10) + u8(0) + u8(0)),
        ("v1_reject_usb_up.0",
         u8(1) + u8(SUB_UP) + u16(UP_FIXED + 64) + u64(GATEWAY) + u64(PROXY) +
         u8(3) + v1head + filler("m", 40)),
    ]
    for name, data in seeds:
        (CORPUS / name).write_bytes(data)

    write_manifest(OUT_WIRE, WIRE, FMT_WIRE,
                   "Wire relay lane v2: 32 B objects, 18 B chunks/replies, "
                   "24 B epoch query/reply.")
    write_manifest(OUT_USB, USB, FMT_USB,
                   "HostOps join relay family v2 (schema 2): 0x60-0x63 inners.")
    print(f"join-relay-v2: wire {WIRE.counts['valid']} valid, "
          f"{WIRE.counts['invalid']} invalid; usb {USB.counts['valid']} valid, "
          f"{USB.counts['invalid']} invalid; {len(seeds)} fuzz seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
