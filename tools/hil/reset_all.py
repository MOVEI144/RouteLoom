#!/usr/bin/env python3
"""Pulse RTS on chip/MAC-verified rig boards within one short interval."""

import argparse
import json
import pathlib
import sys
import time

import serial

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import flash  # noqa: E402
import rig  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rig", required=True)
    parser.add_argument("--bench", required=True)
    parser.add_argument("--boards", nargs="+", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--hold-s", type=float, default=0.5)
    args = parser.parse_args()
    if args.hold_s < 0.1 or len(set(args.boards)) != len(args.boards):
        parser.error("hold-s must be >=0.1 and board names must be distinct")
    bench = rig.load_rigs(args.rig)[args.bench]
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    for name in args.boards:
        board = bench.boards[name]
        if board.chip not in ("esp32c3", "esp32c5", "esp32c6") or not board.mac:
            parser.error(f"{name}: chip and MAC pin required")
        port, _, status = rig.resolve_board_port(board)
        if status != "ONLINE" or port is None:
            parser.error(f"{name}: port unavailable ({status})")
        identity = flash.preflight_board(board, port, flash.DEFAULT_ESPTOOL,
                                         str(out.parent))
        entries.append({"name": name, "port": port, "identity": identity})
    handles = []
    asserted = []
    released = []
    errors = []
    try:
        for entry in entries:
            device = serial.Serial(port=None, baudrate=115200, timeout=0.1)
            device.dtr = False
            device.rts = False
            device.port = entry["port"]
            device.open()
            handles.append(device)
        for device in handles:
            device.dtr = False
        for device in handles:
            device.rts = True
            asserted.append(time.monotonic_ns())
        time.sleep(args.hold_s)
    finally:
        for device in handles:
            try:
                device.rts = False
                device.dtr = True
                released.append(time.monotonic_ns())
            except (OSError, serial.SerialException) as exc:
                errors.append(str(exc))
            try:
                device.close()
            except OSError as exc:
                errors.append(str(exc))
    result = {"boards": entries, "hold_s": args.hold_s,
              "assert_skew_ms": round((max(asserted) - min(asserted)) / 1e6, 3)
              if asserted else None,
              "release_skew_ms": round((max(released) - min(released)) / 1e6, 3)
              if released else None,
              "errors": errors, "finished_unix": time.time()}
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"boards": args.boards,
                      "assert_skew_ms": result["assert_skew_ms"],
                      "release_skew_ms": result["release_skew_ms"],
                      "errors": errors}))
    return 0 if not errors and len(asserted) == len(entries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
