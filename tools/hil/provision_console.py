#!/usr/bin/env python3
"""Run the SDK v1 office PoP flow on one identified maintenance-console board."""

import argparse
import json
import pathlib
import re
import subprocess
import time

import serial


def exchange(port, command: bytes, label: str, timeout_s: float = 20) -> str:
    port.reset_input_buffer()
    port.write(command + b"\n")
    port.flush()
    print(f"> {label}", flush=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        line = port.readline().decode("utf-8", "replace").strip()
        if not line:
            continue
        if line.startswith(("OK ", "ERR ")):
            print(f"< {line if 'pop_hex=' not in line else 'OK pop_hex=<saved in pop.bin>'}", flush=True)
            return line
        print(f"! {line[:200]}", flush=True)
    raise TimeoutError(f"no console response to {label}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", required=True)
    p.add_argument("--mac", required=True)
    p.add_argument("--chip", choices=("esp32c3", "esp32c5"), required=True)
    p.add_argument("--esptool", default=str(pathlib.Path.home() / ".local/bin/esptool"))
    p.add_argument("--ctl", required=True)
    p.add_argument("--ca-key", required=True)
    p.add_argument("--spec", required=True)
    p.add_argument("--node", required=True)
    p.add_argument("--serial", type=int, required=True)
    p.add_argument("--challenge", required=True)
    p.add_argument("--out-dir", required=True)
    args = p.parse_args()
    if not re.fullmatch(r"[0-9a-fA-F]{16}", args.node):
        p.error("--node must be 16 hex characters")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.challenge):
        p.error("--challenge must be 64 hex characters")
    probe = subprocess.run([args.esptool, "--port", args.port, "chip-id"],
                           capture_output=True, text=True, check=True, timeout=30)
    chip = re.search(r"^Chip type:\s*ESP32-(C3|C5)\b", probe.stdout, re.M)
    mac = re.search(r"^MAC:\s*([0-9a-f:]{17})\s*$", probe.stdout, re.M)
    if not chip or not mac or "esp32" + chip.group(1).lower() != args.chip or \
            mac.group(1).lower() != args.mac.lower():
        raise RuntimeError("chip/MAC preflight mismatch; no console write attempted")
    print(f"preflight {args.chip} {args.mac.lower()} on {args.port}", flush=True)
    out = pathlib.Path(args.out_dir)
    if out.exists():
        raise FileExistsError(out)
    with serial.Serial(args.port, 115200, timeout=0.25) as port:
        port.dtr, port.rts = True, False
        status = exchange(port, b"status", "status")
        if not status.startswith("OK identity=none"):
            raise RuntimeError(f"console not unprovisioned: {status}")
        reply = exchange(port, f"keygen {args.node} {args.challenge}".encode(),
                         "keygen <node> <challenge>", 30)
        match = re.fullmatch(r"OK pop_hex=([0-9a-fA-F]{366})", reply)
        if not match:
            raise RuntimeError(f"keygen failed: {reply}")
        out.mkdir(mode=0o700)
        pop = out / "pop.bin"
        pop.write_bytes(bytes.fromhex(match.group(1)))
        cmd = [args.ctl, "provision-devcert", "--ca-key", args.ca_key,
               "--spec", args.spec, "--node", args.node, "--serial", str(args.serial),
               "--challenge", args.challenge, "--pop", str(pop),
               "--out-dir", str(out / "issued")]
        issued = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        (out / "devcert-command.log").write_text(issued.stdout + issued.stderr)
        if issued.returncode:
            raise RuntimeError(f"provision-devcert failed: {issued.returncode}")
        bundle = (out / "issued/identity-bundle.json").read_bytes()
        sealed = exchange(port, b"identity " + bundle.hex().encode(),
                          f"identity <{len(bundle)} bytes>", 30)
        if not sealed.startswith("OK sealed kid="):
            raise RuntimeError(f"identity seal failed: {sealed}")
        readback = exchange(port, b"status", "status after seal")
        if not readback.startswith("OK identity=sealed"):
            raise RuntimeError(f"identity readback failed: {readback}")
    print(json.dumps({"preflight_chip": args.chip, "preflight_mac": args.mac.lower(),
                      "node": args.node.lower(), "seal": sealed, "readback": readback,
                      "bundle_bytes": len(bundle)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
