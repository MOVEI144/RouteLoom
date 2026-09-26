#!/usr/bin/env python3
"""Capture a known USB Serial/JTAG console across disconnect and wake."""

import argparse
import datetime
import os
import pathlib
import time

import serial

try:
    from . import flash, rig
except ImportError:
    import flash  # type: ignore
    import rig  # type: ignore


def stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", required=True, help="exact /dev/serial/by-id path")
    p.add_argument("--mac", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--seconds", type=float, required=True)
    p.add_argument("--reset-on-connect", action="store_true",
                   help="pulse RTS with DTR low after opening the known board")
    p.add_argument("--reset-after-s", type=float,
                   help="pulse RTS once during capture, after this many seconds")
    p.add_argument("--rig", default="tools/hil/rigs.yaml")
    p.add_argument("--bench")
    p.add_argument("--board")
    args = p.parse_args()
    if args.reset_after_s is not None:
        if args.reset_after_s < 0 or args.reset_after_s >= args.seconds:
            p.error("reset-after-s must be within the capture period")
        if not args.bench or not args.board:
            p.error("a timed reset requires --bench and --board for chip-id preflight")
        board = rig.load_rigs(args.rig)[args.bench].boards[args.board]
        if board.mac.lower() != args.mac.lower() or args.port not in board.port_globs:
            p.error("timed-reset port/MAC is not pinned to the named rig board")
        flash.preflight_board(board, args.port, flash.DEFAULT_ESPTOOL,
                              str(pathlib.Path(args.out).parent))
    mac_parts = args.mac.upper().split(":")
    # ESP32-C6 chip-id reports EUI-64, while its USB by-id name contains
    # the EUI-48 base MAC (the middle FF:FE bytes are omitted).
    port_mac = ":".join(mac_parts[:3] + mac_parts[5:]) if (
        len(mac_parts) == 8 and mac_parts[3:5] == ["FF", "FE"]
    ) else args.mac.upper()
    if port_mac not in args.port or "*" in args.port:
        p.error("port must be one exact by-id path containing the expected MAC")
    started = time.monotonic()
    deadline = started + args.seconds
    reset_done = False
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = None
    partial = b""
    with path.open("w", encoding="utf-8") as log:
        while time.monotonic() < deadline:
            if stream is None:
                if not os.path.exists(args.port):
                    time.sleep(0.1)
                    continue
                try:
                    stream = serial.Serial(args.port, 115200, timeout=0.2)
                    stream.dtr, stream.rts = True, False
                    log.write(f"[{stamp()}] !! connected {args.port}\n")
                    if args.reset_on_connect:
                        stream.dtr = False
                        stream.rts = True
                        time.sleep(0.1)
                        stream.rts = False
                        stream.dtr = True
                        log.write(f"[{stamp()}] !! reset pulse (RTS, DTR low)\n")
                    log.flush()
                except (OSError, serial.SerialException) as exc:
                    log.write(f"[{stamp()}] !! open failed: {exc}\n")
                    log.flush()
                    time.sleep(0.2)
                    continue
            try:
                if (args.reset_after_s is not None and not reset_done and
                        time.monotonic() >= started + args.reset_after_s):
                    stream.dtr = False
                    stream.rts = True
                    log.write(f"[{stamp()}] !! reset assert (RTS, DTR low)\n")
                    log.flush()
                    time.sleep(0.12)
                    stream.rts = False
                    stream.dtr = True
                    log.write(f"[{stamp()}] !! reset released\n")
                    log.flush()
                    reset_done = True
                data = stream.read(4096)
            except (OSError, serial.SerialException) as exc:
                log.write(f"[{stamp()}] !! disconnected: {exc}\n")
                log.flush()
                stream.close()
                stream = None
                partial = b""
                continue
            partial += data
            while b"\n" in partial:
                line, partial = partial.split(b"\n", 1)
                log.write(f"[{stamp()}] {line.decode('utf-8', 'replace').rstrip()}\n")
                log.flush()
        if stream is not None:
            stream.close()
        log.write(f"[{stamp()}] !! capture finished\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
