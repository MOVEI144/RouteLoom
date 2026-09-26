#!/usr/bin/env python3
"""Pulse reset on several chip/MAC-pinned USB Serial/JTAG boards together.

Stop the host daemon and other serial readers first. This records the reset
skew and USB re-enumeration; traffic after reboot is measured separately.
"""

import argparse
import datetime
import json
import pathlib
import time

import serial

import flash
import rig


def stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rig", required=True)
    parser.add_argument("--bench", required=True)
    parser.add_argument("--boards", nargs="+", required=True)
    parser.add_argument("--hold-s", type=float, default=0.5)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.hold_s < 0.1 or len(args.boards) != len(set(args.boards)):
        parser.error("hold-s must be >= 0.1 and boards must be unique")
    boards = rig.load_rigs(args.rig)[args.bench].boards
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    selected = []
    for name in args.boards:
        board = boards[name]
        if board.chip not in ("esp32c3", "esp32c5", "esp32c6") or not board.mac:
            parser.error(f"{name} is not a pinned C3/C5/C6")
        port, _, state = rig.resolve_board_port(board)
        if state != "ONLINE" or port is None:
            raise RuntimeError(f"{name} unavailable: {state}")
        identity = flash.preflight_board(board, port, flash.DEFAULT_ESPTOOL, str(out))
        selected.append((name, board, port, identity))
    streams = []
    record = {"started": stamp(), "hold_s": args.hold_s, "boards": [],
              "assert_skew_ms": None, "release_skew_ms": None}
    try:
        for name, board, port, identity in selected:
            device = serial.Serial(port=None, baudrate=115200, timeout=0.2)
            device.dtr, device.rts = True, False
            device.port = port
            device.open()
            streams.append(device)
            record["boards"].append({"name": name, "port": port,
                                     "identity": identity})
        asserted = []
        for device, row in zip(streams, record["boards"]):
            device.dtr = False
            device.rts = True
            tick = time.monotonic_ns()
            row["asserted"] = stamp()
            asserted.append(tick)
        time.sleep(args.hold_s)
        released = []
        for device, row in zip(streams, record["boards"]):
            device.rts = False
            device.dtr = True
            tick = time.monotonic_ns()
            row["released"] = stamp()
            released.append(tick)
        record["assert_skew_ms"] = round((max(asserted) - min(asserted)) / 1e6, 3)
        record["release_skew_ms"] = round((max(released) - min(released)) / 1e6, 3)
    finally:
        for device in streams:
            try:
                device.rts, device.dtr = False, True
                device.close()
            except (OSError, serial.SerialException):
                pass
    time.sleep(2)
    for row, (_, board, _, _) in zip(record["boards"], selected):
        port, _, state = rig.resolve_board_port(board)
        row["after_state"] = state
        row["after_port"] = port
    record["finished"] = stamp()
    (out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))
    return 0 if all(row["after_state"] == "ONLINE" for row in record["boards"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
