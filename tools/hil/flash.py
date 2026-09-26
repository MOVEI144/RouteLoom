#!/usr/bin/env python3
"""Flash a built RouteLoom firmware image to a named rig board.

Reads ``firmware/<app>/build/flasher_args.json`` (written by idf.py) for the
real offsets/files — the same source ``idf.py flash`` uses — and invokes
``esptool write-flash`` directly. Falls back to the standard single-app
offsets (bootloader 0x0, partition table 0x8000, app 0x10000) only when the
JSON is absent, and says so loudly in the log.

After flashing, esptool's ``--after hard-reset`` reboots the board; when the
board has a readable console (``console != none``) the boot log is captured
to ``<out>/<board>-boot.log`` for ``--boot-seconds``. The bridge node logs
to UART0 which is not wired on the bench — its boot capture is skipped by
config, not by silence (see rigs.yaml).

Usage:
    python3 tools/hil/flash.py --rig tools/hil/rigs.yaml --bench bench-a \
        --board ref-a [--app-only] [--out artifacts/hil/flash]

Hardware note: first used on identified C3 boards on 2026-09-26. Flash
manifests and boot logs are retained with that run's report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from typing import Optional

try:
    from . import rig as rig_mod
    from . import capture as capture_mod
except ImportError:  # running as a script: tools/hil on sys.path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import rig as rig_mod  # type: ignore
    import capture as capture_mod  # type: ignore

DEFAULT_ESPTOOL = os.path.expanduser("~/.local/bin/esptool")
DEFAULT_TIMEOUT_S = 120.0
DEFAULT_BOOT_SECONDS = 8.0

# Console lines that mean the firmware started but must count as a failed
# start. The ESP-NOW runtime logs BOOT_HEAP_BELOW_FLOOR when the free heap
# after Wi-Fi/PHY/ESP-NOW start is under CONFIG_ROUTELOOM_BOOT_HEAP_FLOOR_BYTES
# (issue #166); the other two are the Wi-Fi/PHY allocation failures seen on
# the 2026-09-26 bench before the fix.
BOOT_FAILURE_MARKERS = (
    "BOOT_HEAP_BELOW_FLOOR",
    "esp_wifi_init failed",
    "failed to allocate memory for RF calibration",
)


def boot_log_failures(text: str) -> list[str]:
    """Boot-log lines that mark a failed start (issue #166), in order."""
    return [line.rstrip() for line in text.splitlines()
            if any(marker in line for marker in BOOT_FAILURE_MARKERS)]

# Standard bootloader/partition-table offsets. Both firmware apps use a
# custom partitions.csv (single app + the "rlsec" security NVS partition,
# issue #37); the partition table itself stays at 0x8000, and the app offset
# comes from flasher_args.json.
FALLBACK_FLASH_FILES = {
    "0x0": "bootloader/bootloader.bin",
    "0x8000": "partition_table/partition-table.bin",
}


class FlashError(RuntimeError):
    pass


def preflight_board(board: "rig_mod.Board", port: str, esptool: str,
                    out_dir: str) -> dict:
    """Reidentify the device immediately before any write to avoid port drift."""
    if not board.mac or board.chip not in ("esp32c3", "esp32c5", "esp32c6", "esp32s3"):
        raise FlashError("preflight requires a pinned chip and MAC")
    mac_octets = 8 if board.chip == "esp32c6" else 6
    if re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){" +
                    str(mac_octets - 1) + r"}", board.mac) is None:
        raise FlashError("preflight expected MAC has the wrong format")
    cmd = [esptool, "--port", port, "chip-id"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    output = (result.stdout or "") + (result.stderr or "")
    path = os.path.join(out_dir, f"flash-{board.name}-preflight.log")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"$ {' '.join(cmd)}\n{output}")
    def identify(text: str) -> tuple[Optional[str], Optional[str]]:
        chip = re.search(r"^Chip type:\s*ESP32-(C3|S3|C5|C6)(?!\d)", text, re.I | re.M)
        # C6 reports an EUI-64 in the MAC field; C3/C5 report EUI-48.
        mac = re.search(r"^MAC:\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5,7})\s*$", text, re.I | re.M)
        return ("esp32" + chip.group(1).lower() if chip else None,
                mac.group(1).lower() if mac else None)

    detected_chip, detected_mac = identify(output)
    if result.returncode != 0 or detected_chip != board.chip or detected_mac != board.mac.lower():
        raise FlashError(
            f"preflight mismatch on {port}: chip={detected_chip}, "
            f"MAC={detected_mac}, expected={board.chip}/{board.mac} "
            f"(see {path})"
        )
    security_cmd = [esptool, "--chip", board.chip, "--port", port,
                    "get-security-info"]
    security = subprocess.run(security_cmd, capture_output=True, text=True, timeout=30)
    security_output = (security.stdout or "") + (security.stderr or "")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"\n$ {' '.join(security_cmd)}\n{security_output}")
    security_lines = {line.strip() for line in security_output.splitlines()}
    security_chip, security_mac = identify(security_output)
    if (security.returncode != 0 or security_chip != board.chip or
            security_mac != board.mac.lower() or
            "Secure Boot: Disabled" not in security_lines or
            "Flash Encryption: Disabled" not in security_lines):
        raise FlashError(f"preflight identity or security state changed or unknown (see {path})")
    return {"chip": detected_chip, "mac": detected_mac,
            "log": os.path.relpath(path, out_dir)}


def load_flasher_args(build_dir: str) -> dict:
    """Parse build/flasher_args.json produced by idf.py build."""
    path = os.path.join(build_dir, "flasher_args.json")
    if not os.path.isfile(path):
        raise FlashError(
            f"{path} not found — build the app first "
            f"(docker run --rm -v <repo>:/project -w /project/firmware/<app> "
            f"espressif/idf:v6.0.3 idf.py build)"
        )
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_write_flash_cmd(
    build_dir: str,
    port: str,
    esptool: str,
    chip: Optional[str],
    flash_baud: int,
    app_only: bool,
) -> tuple[list[str], dict, bool]:
    """Construct the esptool argv. Returns (argv, flash_files, used_fallback).

    ``flash_files`` maps offset -> absolute path for the manifest.
    """
    args = load_flasher_args(build_dir)
    extra = args.get("extra_esptool_args", {})
    chip = chip or extra.get("chip") or None
    before = extra.get("before", "default-reset")
    after = extra.get("after", "hard-reset")

    flash_files = args.get("flash_files") or {}
    used_fallback = not flash_files
    if app_only:
        app_entry = args.get("app") or {}
        offset = app_entry.get("offset")
        file = app_entry.get("file")
        if not offset or not file:
            raise FlashError("app-only requires an explicit app offset and file")
        flash_files = {offset: file}
    elif used_fallback:
        flash_files = dict(FALLBACK_FLASH_FILES)
        flash_files["0x10000"] = _find_app_bin(build_dir)

    cmd = [esptool]
    if chip:
        cmd += ["--chip", chip]
    cmd += [
        "--port", port,
        "--baud", str(flash_baud),
        "--before", before,
        "--after", after,
        "write-flash",
    ]
    cmd += [str(x) for x in args.get("write_flash_args", [])]
    resolved = {}
    for offset, rel in flash_files.items():
        path = rel if os.path.isabs(rel) else os.path.join(build_dir, rel)
        if not os.path.isfile(path):
            raise FlashError(f"flash file missing: {path}")
        resolved[offset] = path
        cmd += [offset, path]
    return cmd, resolved, used_fallback


def _find_app_bin(build_dir: str) -> str:
    bins = [
        f for f in os.listdir(build_dir)
        if f.endswith(".bin") and "bootloader" not in f
        and "partition" not in f
    ]
    if not bins:
        raise FlashError(f"no app .bin found in {build_dir}")
    if len(bins) > 1:
        raise FlashError(f"ambiguous app .bin in {build_dir}: {bins}")
    return os.path.join(build_dir, bins[0])


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def flash_board(
    board: "rig_mod.Board",
    port: str,
    out_dir: str,
    esptool: str = DEFAULT_ESPTOOL,
    app_only: bool = False,
    boot_seconds: float = DEFAULT_BOOT_SECONDS,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    repo: str = rig_mod.REPO_ROOT,
    image_dir: Optional[str] = None,
) -> dict:
    """Flash one board. Returns a manifest dict for the report."""
    os.makedirs(out_dir, exist_ok=True)
    preflight = preflight_board(board, port, esptool, out_dir)
    build_dir = os.path.join(image_dir, "build") if image_dir else board.build_dir(repo)
    cmd, files, fallback = build_write_flash_cmd(
        build_dir, port, esptool, board.chip or None, board.flash_baud, app_only
    )
    manifest = {
        "board": board.name,
        "app": board.app,
        "port": port,
        "chip": board.chip,
        "preflight": preflight,
        "app_only": app_only,
        "fallback_offsets": fallback,
        "cmd": cmd,
        "files": {off: {"path": p, "sha256": sha256_file(p)}
                  for off, p in files.items()},
        "started_utc": capture_mod.utc_stamp(),
        "ok": False,
        "esptool_log": None,
        "boot_log": None,
        "error": None,
    }

    log_path = os.path.join(out_dir, f"flash-{board.name}-esptool.log")
    manifest["esptool_log"] = os.path.relpath(log_path, out_dir)
    with open(log_path, "w", encoding="utf-8") as log:
        log.write(f"$ {' '.join(cmd)}\n")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_s
            )
            log.write(proc.stdout or "")
            log.write(proc.stderr or "")
            manifest["exit_code"] = proc.returncode
            if proc.returncode != 0:
                manifest["error"] = f"esptool exit {proc.returncode}"
                return manifest
        except subprocess.TimeoutExpired:
            log.write(f"\n!! timed out after {timeout_s}s\n")
            manifest["error"] = f"esptool timed out after {timeout_s}s"
            return manifest
        except OSError as exc:
            log.write(f"\n!! exec failed: {exc}\n")
            manifest["error"] = f"exec failed: {exc}"
            return manifest

    # Post-flash boot capture: esptool --after hard-reset already rebooted
    # the board; we listen for boot_seconds on consoles that exist.
    if board.console != "none" and boot_seconds > 0:
        boot_path = os.path.join(out_dir, f"flash-{board.name}-boot.log")
        manifest["boot_log"] = os.path.relpath(boot_path, out_dir)
        cap = capture_mod.SerialCapture(
            f"boot-{board.name}", port, board.baud, boot_path,
            dtr=board.dtr, rts=board.rts,
        )
        try:
            cap.start()
            time.sleep(boot_seconds)
        except capture_mod.CaptureError as exc:
            manifest["error"] = f"flashed, but boot capture failed: {exc}"
            return manifest
        finally:
            cap.stop()
    if manifest["boot_log"] is not None:
        with open(boot_path, encoding="utf-8", errors="replace") as fh:
            failures = boot_log_failures(fh.read())
        if failures:
            manifest["boot_failures"] = failures
            manifest["error"] = ("flashed, but the boot log reports a failed start: "
                                 + failures[0])
            return manifest
    manifest["ok"] = True
    manifest["finished_utc"] = capture_mod.utc_stamp()
    return manifest


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rig", required=True)
    parser.add_argument("--bench", required=True)
    parser.add_argument("--board", required=True, help="role name in the bench")
    parser.add_argument("--esptool", default=DEFAULT_ESPTOOL)
    parser.add_argument("--app-only", action="store_true",
                        help="flash only the app partition (0x10000)")
    parser.add_argument("--boot-seconds", type=float, default=DEFAULT_BOOT_SECONDS,
                        help="post-flash boot capture length (0 disables)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--out", default=os.path.join(
        rig_mod.REPO_ROOT, "artifacts", "hil", "flash"))
    parser.add_argument("--image-dir", help="bench image directory containing build/flasher_args.json")
    parser.add_argument("--capture-boot", action="store_true",
                        help="capture USB boot text for a diagnostic image whose console is on USB")
    args = parser.parse_args(argv)

    rigs = rig_mod.load_rigs(args.rig)
    if args.bench not in rigs:
        print(f"error: bench {args.bench!r} not in {args.rig}", file=sys.stderr)
        return 2
    bench = rigs[args.bench]
    if args.board not in bench.boards:
        print(f"error: board {args.board!r} not in bench {args.bench!r} "
              f"(have: {', '.join(sorted(bench.boards))})", file=sys.stderr)
        return 2
    board = bench.boards[args.board]
    if args.capture_boot:
        board.console = "usb-serial-jtag"

    port, matches, status = rig_mod.resolve_board_port(board)
    if status != "ONLINE":
        print(f"board {args.board!r} is {status} "
              f"(matches: {matches or 'none'}) — nothing flashed", file=sys.stderr)
        return 3

    manifest = flash_board(
        board, port, args.out, esptool=args.esptool, app_only=args.app_only,
        boot_seconds=args.boot_seconds, timeout_s=args.timeout,
        image_dir=args.image_dir,
    )
    manifest_path = os.path.join(args.out, f"flash-{board.name}.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    if manifest["ok"]:
        print(f"flashed {board.app} -> {board.name} on {port}; "
              f"manifest {manifest_path}")
        return 0
    print(f"flash FAILED: {manifest['error']} (see {manifest_path})",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
