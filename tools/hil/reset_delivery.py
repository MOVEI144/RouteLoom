#!/usr/bin/env python3
"""Hold a verified reference board in reset and measure delivery recovery."""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

import serial

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import flash  # noqa: E402
import rig  # noqa: E402


TERMINAL = {"delivered", "expired", "failed", "rejected", "cancelled"}


def ctl(base: list[str], *args: str) -> dict:
    result = subprocess.run(base + list(args), capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise RuntimeError(f"routeloomctl {' '.join(args)}: {result.stderr or result.stdout}")
    return json.loads(result.stdout)


def probe(base: list[str], destination: int, label: str, deadline: float) -> dict:
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        reply = ctl(base, "send", str(destination), label.encode().hex())
        if reply.get("accepted"):
            break
        retry = re.search(r"rate limited .* retry in (\d+) ms", str(reply.get("error", "")))
        if retry is None:
            return {"label": label, "admission_attempts": attempts, "response": reply}
        time.sleep(min(int(retry.group(1)) / 1000 + 0.1, 10))
    else:
        return {"label": label, "admission_attempts": attempts,
                "response": {"accepted": False, "error": "admission timeout"}}
    admitted = time.monotonic()
    row = {"label": label, "admission_attempts": attempts,
           "response": reply, "admitted_unix": time.time()}
    request = reply["request"]
    while time.monotonic() - admitted < 9:
        delivery = next((d for d in ctl(base, "deliveries").get("deliveries", [])
                         if d.get("request") == request), None)
        if delivery and delivery.get("state") in TERMINAL:
            row["delivery"] = delivery
            row["latency_ms"] = round((time.monotonic() - admitted) * 1000, 2)
            return row
        time.sleep(0.05)
    row["delivery"] = {"state": "poll_timeout"}
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rig", required=True)
    parser.add_argument("--bench", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--ctl", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--destination", type=int, required=True)
    parser.add_argument("--hold-s", type=float, default=3)
    parser.add_argument("--recovery-timeout-s", type=float, default=60)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.hold_s < 1 or args.recovery_timeout_s <= 0:
        parser.error("hold-s must be >=1 and recovery-timeout-s positive")
    board = rig.load_rigs(args.rig)[args.bench].boards[args.board]
    if board.role != "reference" or board.chip not in ("esp32c3", "esp32c5", "esp32c6") or not board.mac:
        parser.error("reset requires a pinned C3/C5/C6 reference board")
    port, _, status = rig.resolve_board_port(board)
    if status != "ONLINE" or port is None:
        parser.error(f"target port unavailable: {status}")
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    identity = flash.preflight_board(board, port, flash.DEFAULT_ESPTOOL, str(out.parent))
    base = [args.ctl, "--socket", args.socket]
    record = {"board": args.board, "identity": identity, "port": port,
              "destination": args.destination, "hold_s": args.hold_s,
              "started_unix": time.time()}
    device = serial.Serial(port=None, baudrate=115200, timeout=0.1)
    device.dtr = False
    device.rts = False
    device.port = port
    device.open()
    held_at = time.monotonic()
    try:
        device.dtr = False
        device.rts = True
        held_at = time.monotonic()
        record["reset_held_unix"] = time.time()
        record["during"] = probe(base, args.destination, "R2-during-reset",
                                 held_at + args.hold_s)
        remaining = held_at + args.hold_s - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    finally:
        device.rts = False
        device.dtr = True
        released = time.monotonic()
        record["actual_hold_s"] = round(released - held_at, 3)
        record["reset_released_unix"] = time.time()
        device.close()
    deadline = released + args.recovery_timeout_s
    record["after"] = []
    while time.monotonic() < deadline:
        row = probe(base, args.destination, f"R2-after-{len(record['after'])}", deadline)
        record["after"].append(row)
        if row.get("delivery", {}).get("state") == "delivered":
            record["recovery_s"] = round(time.monotonic() - released, 3)
            break
        time.sleep(1)
    else:
        record["recovery_s"] = None
    record["finished_unix"] = time.time()
    out.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"board": args.board, "destination": args.destination,
                      "during": record["during"].get("delivery", {}).get("state"),
                      "after_probes": len(record["after"]),
                      "recovery_s": record["recovery_s"]}))
    return 0 if record["recovery_s"] is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
