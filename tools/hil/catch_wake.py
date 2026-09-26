#!/usr/bin/env python3
"""Catch a briefly enumerating HIL board and recover its application image.

This is for a board whose old sleep image exposes USB for too short a time
for a manual flash. The exact USB by-id path, chip and MAC are required.
No flash is attempted until both esptool identity probes and the security
probe agree with those pinned values.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import time

try:
    # With the esptool virtualenv interpreter this imports before the brief
    # USB enumeration, avoiding the CLI process start inside the wake window.
    import esptool
except ImportError:
    esptool = None

try:
    from .flash import build_write_flash_cmd, sha256_file
except ImportError:
    from flash import build_write_flash_cmd, sha256_file


def run(cmd: list[str], timeout: float) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired as exc:
        return 124, f"timeout after {timeout}s: {exc}\n"


def fast_probe(cmd: list[str]) -> tuple[int, str]:
    if esptool is None:
        raise RuntimeError("fast probe requires the esptool Python environment")
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            esptool.main(cmd[1:])
    except (SystemExit, Exception) as exc:
        code = exc.code if isinstance(exc, SystemExit) and isinstance(exc.code, int) else 1
        return code, output.getvalue() + f"\n{type(exc).__name__}: {exc}\n"
    return 0, output.getvalue()


def identity(output: str) -> tuple[str | None, str | None]:
    chip = re.search(r"^Chip type:\s*ESP32-(C3|C5|C6)\b", output, re.I | re.M)
    mac = re.search(r"^MAC:\s*([0-9a-f:]+)\s*$", output, re.I | re.M)
    return (f"esp32{chip.group(1).lower()}" if chip else None,
            mac.group(1).lower() if mac else None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="exact USB by-id path")
    parser.add_argument("--chip", required=True, choices=("esp32c3", "esp32c5", "esp32c6"))
    parser.add_argument("--mac", required=True, help="expected chip-id MAC")
    parser.add_argument("--image-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--seconds", type=int, default=2400)
    parser.add_argument("--esptool", default=os.path.expanduser("~/.local/bin/esptool"))
    parser.add_argument("--fast-probe", action="store_true",
                        help="preload esptool; run with its virtualenv Python")
    parser.add_argument("--early-tty", help="optional ttyACM path checked before udev by-id")
    parser.add_argument("--usb-sysfs", help="exact USB device sysfs path for early tty verification")
    args = parser.parse_args()
    if args.fast_probe and esptool is None:
        parser.error("--fast-probe requires esptool importable in this Python")
    if not args.port.startswith("/dev/serial/by-id/usb-Espressif_"):
        parser.error("port must be an exact Espressif USB by-id path")
    if bool(args.early_tty) != bool(args.usb_sysfs):
        parser.error("--early-tty and --usb-sysfs must be supplied together")
    if args.early_tty and (re.fullmatch(r"/dev/ttyACM\d+", args.early_tty) is None or
                           not args.usb_sysfs.startswith("/sys/bus/usb/devices/")):
        parser.error("early tty/sysfs paths must be exact USB ACM device paths")
    build_dir = os.path.join(args.image_dir, "build")
    config_path = os.path.join(args.image_dir, "sdkconfig")
    with open(config_path, encoding="utf-8") as handle:
        config = handle.read()
    if (f'CONFIG_IDF_TARGET="{args.chip}"' not in config or
            re.search(r"^CONFIG_SECURE_BOOT=y$|^CONFIG_SECURE_FLASH_ENC_ENABLED=y$|"
                      r"^CONFIG_FLASH_ENCRYPTION_ENABLED=y$", config, re.M)):
        parser.error("image target/security configuration failed preflight")
    os.makedirs(args.out, exist_ok=True)
    log_path = os.path.join(args.out, "catch-wake.log")
    deadline = time.monotonic() + args.seconds
    attempt = 0

    def available_port() -> str | None:
        if args.early_tty and os.path.exists(args.early_tty):
            interface = os.path.realpath(
                f"/sys/class/tty/{os.path.basename(args.early_tty)}/device")
            usb_device = os.path.realpath(args.usb_sysfs)
            try:
                with open(os.path.join(usb_device, "serial"), encoding="ascii") as handle:
                    serial_number = handle.read().strip().lower()
                with open(os.path.join(usb_device, "idVendor"), encoding="ascii") as handle:
                    vendor = handle.read().strip().lower()
                with open(os.path.join(usb_device, "idProduct"), encoding="ascii") as handle:
                    product = handle.read().strip().lower()
            except OSError:
                pass
            else:
                if (interface.startswith(usb_device + "/") and
                        os.path.basename(interface).startswith(
                            os.path.basename(usb_device) + ":") and
                        serial_number == args.mac.lower() and vendor == "303a" and
                        product == "1001"):
                    return args.early_tty
        return args.port if os.path.exists(args.port) else None

    with open(log_path, "a", encoding="utf-8", buffering=1) as log:
        log.write(f"start port={args.port} chip={args.chip} mac={args.mac} image={args.image_dir}\n")
        while time.monotonic() < deadline:
            target_port = available_port()
            if target_port is None:
                time.sleep(0.005)
                continue
            attempt += 1
            chip_cmd = [args.esptool, "--chip", args.chip, "--port", target_port,
                        "--connect-attempts", "1", "--before", "default-reset",
                        "--after", "no-reset", "chip-id"]
            code, output = fast_probe(chip_cmd) if args.fast_probe else run(chip_cmd, 12)
            log.write(f"attempt={attempt} port={target_port} chip-id exit={code}\n{output}\n")
            print(f"attempt {attempt}: chip-id exit={code} identity={identity(output)}", flush=True)
            if code != 0 or identity(output) != (args.chip, args.mac.lower()):
                # Wait for this enumeration to end before retrying on the next wake.
                while available_port() is not None and time.monotonic() < deadline:
                    time.sleep(0.01)
                continue
            security_cmd = [args.esptool, "--chip", args.chip, "--port", target_port,
                            "--before", "no-reset", "--after", "no-reset",
                            "get-security-info"]
            code, security = run(security_cmd, 15)
            log.write(f"security exit={code}\n{security}\n")
            security_lines = {line.strip() for line in security.splitlines()}
            if (code != 0 or identity(security) != (args.chip, args.mac.lower()) or
                    "Secure Boot: Disabled" not in security_lines or
                    "Flash Encryption: Disabled" not in security_lines):
                print("security or second identity probe failed; no write", flush=True)
                return 2
            cmd, files, fallback = build_write_flash_cmd(
                build_dir, target_port, args.esptool, args.chip, 460800, False)
            cmd[cmd.index("--before") + 1] = "no-reset"
            cmd[cmd.index("--after") + 1] = "hard-reset"
            manifest = {
                "port": target_port, "chip": args.chip, "mac": args.mac.lower(),
                "attempt": attempt, "fallback_offsets": fallback,
                "files": {offset: {"path": path, "sha256": sha256_file(path)}
                          for offset, path in files.items()},
                "command": cmd,
            }
            with open(os.path.join(args.out, "catch-wake-manifest.json"), "w", encoding="utf-8") as handle:
                json.dump(manifest, handle, indent=2)
                handle.write("\n")
            code, flashed = run(cmd, 180)
            log.write(f"flash exit={code}\n{flashed}\n")
            print(f"flash exit={code}", flush=True)
            return 0 if code == 0 else 3
    print(f"timed out after {args.seconds}s; no write", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
