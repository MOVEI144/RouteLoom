#!/usr/bin/env python3
"""Time the first host delivery after each pinned reference-node USB wake."""

import argparse
import datetime
import json
import pathlib
import re
import subprocess
import time


TERMINAL = {"delivered", "expired", "failed", "rejected", "cancelled"}


def stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def ctl(base: list[str], *args: str) -> dict:
    run = subprocess.run(base + list(args), capture_output=True, text=True, timeout=12)
    if run.returncode:
        raise RuntimeError(f"{' '.join(args)}: {run.stderr or run.stdout}")
    return json.loads(run.stdout)


def probe(base: list[str], node: int, cycle: int, attempt: int,
          deadline: float) -> dict:
    row = {"cycle": cycle, "attempt": attempt, "start_utc": stamp()}
    payload = b"RLHILW" + bytes([cycle, attempt])
    while time.monotonic() < deadline:
        reply = ctl(base, "send", str(node), payload.hex())
        if reply.get("accepted"):
            row["request"] = reply["request"]
            row["accepted_utc"] = stamp()
            break
        error = str(reply.get("error", ""))
        limited = re.search(r"rate limited .* retry in (\d+) ms", error)
        if limited is None:
            row["refused"] = error
            return row
        time.sleep(min(max(int(limited.group(1)) / 1000 + 0.1, 0.1), 12))
    else:
        row["refused"] = "admission deadline"
        return row
    poll_deadline = min(deadline, time.monotonic() + 9)
    while time.monotonic() < poll_deadline:
        delivery = next((item for item in ctl(base, "deliveries").get("deliveries", [])
                         if item.get("request") == row["request"]), None)
        if delivery and delivery.get("state") in TERMINAL:
            row["delivery"] = delivery
            row["terminal_utc"] = stamp()
            row["terminal_monotonic_s"] = time.monotonic()
            return row
        time.sleep(0.05)
    row["delivery"] = {"state": "poll_timeout"}
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=pathlib.Path, required=True)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--ctl", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--node", type=int, required=True)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=900)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    mac = args.mac.upper()
    expected_port = ("/dev/serial/by-id/"
                     f"usb-Espressif_USB_JTAG_serial_debug_unit_{mac}-if00")
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac) or \
            str(args.port) != expected_port:
        parser.error("port must be the pinned Espressif USB by-id MAC")
    if args.cycles < 1 or args.cycles > 10 or args.seconds <= 0 or args.node <= 0:
        parser.error("cycles must be 1..10, seconds positive, node positive")
    if not args.port.exists():
        parser.error("pinned board is not present at startup")
    base = [args.ctl, "--socket", args.socket]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + args.seconds
    records = []
    present = True
    lost_at = None
    cycle = 0
    with args.out.open("w", encoding="utf-8", buffering=1) as log:
        while time.monotonic() < deadline and cycle < args.cycles:
            now_present = args.port.exists()
            if present and not now_present:
                lost_at = time.monotonic()
                present = False
            elif not present and now_present:
                absent_s = time.monotonic() - (lost_at or time.monotonic())
                present = True
                if absent_s < 0.5:
                    continue
                wake = time.monotonic()
                record = {"cycle": cycle, "wake_utc": stamp(),
                          "usb_absent_s": round(absent_s, 3), "attempts": [],
                          "first_delivery_after_wake_s": None}
                cycle_deadline = min(deadline, wake + 110)
                for attempt in range(4):
                    if time.monotonic() >= cycle_deadline or not args.port.exists():
                        break
                    try:
                        row = probe(base, args.node, cycle, attempt, cycle_deadline)
                    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                        row = {"cycle": cycle, "attempt": attempt, "error": str(exc)}
                    record["attempts"].append(row)
                    if row.get("delivery", {}).get("state") == "delivered":
                        record["first_delivery_after_wake_s"] = round(
                            row["terminal_monotonic_s"] - wake, 3)
                        break
                records.append(record)
                log.write(json.dumps(record, separators=(",", ":")) + "\n")
                cycle += 1
            time.sleep(0.05)
    summary = {"requested_cycles": args.cycles, "observed_wakes": len(records),
               "delivered_cycles": sum(x["first_delivery_after_wake_s"] is not None
                                       for x in records), "elapsed_s": round(time.monotonic() - started, 2)}
    args.out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 0 if summary["delivered_cycles"] == args.cycles else 1


if __name__ == "__main__":
    raise SystemExit(main())
