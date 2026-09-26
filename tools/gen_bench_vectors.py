#!/usr/bin/env python3
"""Regenerate protocol/bench-golden/*.json — shared wire vectors for the
RLB1 bench application codec (design-devflow.md §5.2).

The layouts mirror
components/routeloom_bench/{include/routeloom/bench/protocol.hpp,
src/protocol.cpp} and host/routeloom-protocol/src/bench.rs. All integers are
big-endian; the body CRC is ISO HDLC CRC32 over the body bytes only (zlib
crc32 is the same function). These vectors pin byte layouts only — the
encode/decode pairs of the C++ and Rust codecs must replay every wire_hex
identically and refuse the negative vectors with the named verdict.
"""
from __future__ import annotations

import binascii
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "bench-golden"


def u8(v):
    return struct.pack(">B", v)


def u16(v):
    return struct.pack(">H", v)


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def crc32(body: bytes) -> bytes:
    return u32(binascii.crc32(body) & 0xFFFFFFFF)


MAGIC = b"RLB1"
VERSION = 1
HEADER = 32

# Opcodes (routeloom::bench::Opcode / routeloom_protocol::bench::Opcode).
HELLO = 0x01
CAPABILITIES = 0x02
ECHO_REQUEST = 0x10
ECHO_REPLY = 0x11
COUNT_ONLY = 0x20
COUNT_GET = 0x21
COUNT_STATUS = 0x22
ROLLCALL = 0x30
STATUS_GET = 0x40
STATUS = 0x41
PEER_SEND_START = 0x50
PEER_SEND_STATUS = 0x51
PEER_SEND_STOP = 0x52
COUNTER_RESET = 0x60
FAULT_SET = 0x61
RESET_REQUEST = 0x70
RESET_ACK = 0x71

OPCODES = [HELLO, CAPABILITIES, ECHO_REQUEST, ECHO_REPLY, COUNT_ONLY,
           COUNT_GET, COUNT_STATUS, ROLLCALL, STATUS_GET, STATUS,
           PEER_SEND_START, PEER_SEND_STATUS, PEER_SEND_STOP, COUNTER_RESET,
           FAULT_SET, RESET_REQUEST, RESET_ACK]

FLAG_RESPONSE = 0x0001
FLAG_DUPLICATE = 0x0002
FLAG_LATE = 0x0004
FLAG_FAULT = 0x0008

RUN = bytes.fromhex("00112233445566778899aabbccddeeff")
RUN_B = bytes.fromhex("deadbeefcafe01020304050607080910")
BOOT = 0x000000B0071D0001
BOOT2 = 0x000000B0071D0002


def wire(opcode: int, flags: int, run: bytes, seq: int, body: bytes) -> bytes:
    return (MAGIC + u8(VERSION) + u8(opcode) + u16(flags) + run + u32(seq) +
            crc32(body) + body)


def vector(name, opcode, flags, run, seq, body, note, expect="ok"):
    w = wire(opcode, flags, run, seq, body)
    return {
        "name": name,
        "opcode": opcode,
        "flags": flags,
        "run_uuid_hex": run.hex(),
        "sequence": seq,
        "body_hex": body.hex(),
        "wire_hex": w.hex(),
        "expect": expect,
        "note": note,
    }


def negative(name, wire_bytes: bytes, expect: str, note: str):
    return {
        "name": name,
        "expect": expect,
        "wire_hex": wire_bytes.hex(),
        "note": note,
    }


def capabilities_body():
    return (u8(1) + u8(1) + u8(96) + u8(95) + u8(64) + u8(2) + u8(4) +
            u8(1) + u64(BOOT) + u32(0xC0FFEE01) + u32(0) +
            u8(len(OPCODES)) + bytes(OPCODES))


def count_status_body():
    return (u8(1) + u32(9) + u32(99) + u32(2) + u32(1) + u32(100) +
            u32(900) + u32(10) + u64(0xABCD))


def peer_send_start_body():
    return (u64(BOOT) + u64(0xB) + u32(100) + u16(64) + u8(24) +
            u32(0xDEADBEEF) + u32(250) + u32(30000) + u8(1))


def peer_send_status_body():
    return (u8(1) + u8(1) + u16(64) + u16(3) + u16(3) + u16(2) + u16(0) +
            u16(1) + u32(1000) + u32(1500))


def status_body():
    # sample_seq 3, boot, page 5 (generator), page_count 7, then the
    # generator page fields the firmware emits.
    fields = (u8(1) + u64(0x1) + RUN + u64(0xB) + u32(100) + u16(64) +
              u16(3) + u16(3) + u16(2) + u16(0) + u16(1) + u16(3) +
              u32(1000) + u32(1500) + u32(250) + u8(0))
    return u16(3) + u64(BOOT) + u8(5) + u8(7) + fields


def fault_set_body():
    return u64(BOOT) + u8(2) + u32(5000) + u32(250)


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    vectors = [
        vector("hello", HELLO, 0, RUN, 1, b"",
               "host opens a run; the reply is a CAPABILITIES"),
        vector("capabilities", CAPABILITIES, FLAG_RESPONSE, RUN, 1,
               capabilities_body(),
               "device answer: protocol bounds, queue depths, opcode list, "
               "boot incarnation, digests"),
        vector("echo_request", ECHO_REQUEST, 0, RUN, 7, b"ping",
               "opaque echo body, stored for the reply"),
        vector("echo_reply", ECHO_REPLY, FLAG_RESPONSE, RUN, 7, b"ping",
               "echo reply reuses request run/seq; response flag makes it "
               "unechoable"),
        vector("echo_reply_duplicate", ECHO_REPLY,
               FLAG_RESPONSE | FLAG_DUPLICATE, RUN, 7, b"ping",
               "re-answer to a request already seen inside the run window"),
        vector("count_only", COUNT_ONLY, 0, RUN, 8, bytes(range(24)),
               "counted, never answered"),
        vector("count_get", COUNT_GET, 0, RUN, 9, b"",
               "ask for the header run's reception state"),
        vector("count_status", COUNT_STATUS, FLAG_RESPONSE, RUN, 9,
               count_status_body(),
               "run state: 9 unique packets/99 bytes, 2 duplicates, 1 CRC "
               "invalid, window base 10"),
        vector("rollcall", ROLLCALL, 0, RUN, 10, u8(0xFF),
               "group-carried point call; page 0xFF = no status request"),
        vector("rollcall_page", ROLLCALL, 0, RUN, 11, u8(0),
               "rollcall asking for the identity STATUS page"),
        vector("status_get", STATUS_GET, 0, RUN, 12, u8(5),
               "request the generator STATUS page"),
        vector("status", STATUS, FLAG_RESPONSE, RUN, 12, status_body(),
               "bounded STATUS page: shared head (sample_seq/boot/page/"
               "count) + generator fields"),
        vector("peer_send_start", PEER_SEND_START, 0, RUN_B, 1,
               peer_send_start_body(),
               "control: node sends 64 packets of 24 B to node 0xB, "
               "seq from 100, 250 ms apart, 30 s TTL"),
        vector("peer_send_status", PEER_SEND_STATUS, FLAG_RESPONSE, RUN_B, 1,
               peer_send_status_body(),
               "start acknowledgement: accepted counters are admission-time "
               "(final counters live on the generator STATUS page)"),
        vector("peer_send_stop", PEER_SEND_STOP, 0, RUN_B, 2, u64(BOOT),
               "stop the running generator; body is the boot incarnation"),
        vector("counter_reset", COUNTER_RESET, 0, RUN_B, 3, u64(BOOT),
               "zero the app counters only — never SDK session/dedup state"),
        vector("fault_set", FAULT_SET, 0, RUN_B, 4, fault_set_body(),
               "arm echo-delay: hold replies 250 ms for 5 s, then auto-clear"),
        vector("reset_request", RESET_REQUEST, 0, RUN_B, 5,
               u64(BOOT) + u32(300),
               "delayed one-shot reset bound to this boot incarnation"),
        vector("reset_ack", RESET_ACK, FLAG_RESPONSE, RUN_B, 5, u8(1),
               "reset accepted; the device restarts after the delay"),
        vector("unknown_opcode", 0x7F, 0, RUN, 20, b"",
               "well-formed header with an opcode the app does not know: "
               "decode succeeds, opcode_known is false"),
        # Negatives: the same header with its integrity or framing broken.
        negative("truncated",
                 wire(ECHO_REQUEST, 0, RUN, 1, b"ping")[:31],
                 "truncated", "31 bytes: below the 32-byte header"),
        negative("bad_magic",
                 b"RLB0" + wire(ECHO_REQUEST, 0, RUN, 1, b"ping")[4:],
                 "bad_magic", "magic must be exactly 'RLB1'"),
        negative("bad_version",
                 MAGIC + u8(9) + wire(ECHO_REQUEST, 0, RUN, 1, b"ping")[5:],
                 "unsupported_version", "protocol version is 1"),
        negative("bad_crc",
                 wire(ECHO_REQUEST, 0, RUN, 1, b"ping")[:-1] + b"X",
                 "crc_mismatch", "last body byte corrupted"),
    ]

    for index, v in enumerate(vectors, 1):
        (OUT / f"{index:02}_{v['name']}.json").write_text(
            json.dumps(v, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
