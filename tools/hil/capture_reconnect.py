#!/usr/bin/env python3
"""Capture a pinned USB Serial/JTAG console across sleep re-enumerations."""

import argparse
import datetime
import pathlib
import re
import time

import serial


def stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="exact Espressif USB by-id path")
    parser.add_argument("--mac", required=True, help="pinned USB serial MAC (6 bytes)")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--seconds", type=float, required=True)
    args = parser.parse_args()
    mac = args.mac.upper()
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        parser.error("--mac must be a 6-byte colon-separated MAC")
    if args.port != ("/dev/serial/by-id/"
                     f"usb-Espressif_USB_JTAG_serial_debug_unit_{mac}-if00"):
        parser.error("port does not match pinned Espressif USB serial MAC")
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + args.seconds
    connections = 0
    with args.out.open("w", encoding="utf-8", buffering=1) as log:
        def note(message: str) -> None:
            log.write(f"[{stamp()}] {message}\n")

        while time.monotonic() < deadline:
            if not pathlib.Path(args.port).exists():
                time.sleep(0.05)
                continue
            device = serial.Serial(port=None, baudrate=115200, timeout=0.1)
            device.dtr, device.rts = True, False
            device.port = args.port
            try:
                device.open()
            except (OSError, serial.SerialException):
                device.close()
                time.sleep(0.05)
                continue
            connections += 1
            note(f"!! connected {mac} count={connections}")
            partial = b""
            try:
                while time.monotonic() < deadline:
                    try:
                        data = device.read(4096)
                    except (OSError, serial.SerialException) as exc:
                        note(f"!! disconnected {type(exc).__name__}")
                        break
                    if not data:
                        if not pathlib.Path(args.port).exists():
                            note("!! disconnected port absent")
                            break
                        continue
                    partial += data
                    while b"\n" in partial:
                        line, partial = partial.split(b"\n", 1)
                        note(line.decode("utf-8", "replace").rstrip("\r"))
            finally:
                if partial:
                    note(partial.decode("utf-8", "replace") + " (unterminated)")
                device.close()
        note(f"!! capture finished connections={connections}")
    return 0 if connections else 1


if __name__ == "__main__":
    raise SystemExit(main())
