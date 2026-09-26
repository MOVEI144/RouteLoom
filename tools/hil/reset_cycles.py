#!/usr/bin/env python3
"""Reset a verified reference board repeatedly and measure delivery recovery.

Each cycle pulses the board's reset line (RTS, DTR low) on the chip-id
verified USB Serial/JTAG port, then sends N messages through the host daemon
and records every outcome, the time from reset release to the first delivered
message, and the reference console captured on the same port. The bridge is
observed only through the daemon socket (its USB carries the COBS protocol).
"""

import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import threading
import time

import serial

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import flash  # noqa: E402
import rig  # noqa: E402

TERMINAL = {"delivered", "expired", "failed", "rejected", "cancelled"}


def stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def ctl(base: list[str], *args: str) -> dict:
    result = subprocess.run(base + list(args), capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise RuntimeError(f"routeloomctl {' '.join(args)}: {result.stderr or result.stdout}")
    return json.loads(result.stdout)


def probe(base: list[str], destination: int, label: str, admission_deadline: float,
          poll_timeout_s: float, console) -> dict:
    """One send: admission (retrying only on the host rate limit), then poll."""
    attempts = 0
    while True:
        attempts += 1
        reply = ctl(base, "send", str(destination), label.encode().hex())
        if reply.get("accepted"):
            break
        retry = re.search(r"rate limited .* retry in (\d+) ms", str(reply.get("error", "")))
        if retry is None or time.monotonic() >= admission_deadline:
            row = {"label": label, "admission_attempts": attempts, "response": reply,
                   "sent_unix": time.time()}
            console(f"!! send {label} refused: {reply.get('error')}")
            return row
        time.sleep(min(int(retry.group(1)) / 1000 + 0.1, 10))
    admitted = time.monotonic()
    console(f"!! send {label} admitted request={reply.get('request')}")
    row = {"label": label, "admission_attempts": attempts, "response": reply,
           "admitted_unix": time.time()}
    request = reply["request"]
    while time.monotonic() - admitted < poll_timeout_s:
        delivery = next((d for d in ctl(base, "deliveries").get("deliveries", [])
                         if d.get("request") == request), None)
        if delivery and delivery.get("state") in TERMINAL:
            row["delivery"] = delivery
            row["latency_ms"] = round((time.monotonic() - admitted) * 1000, 2)
            console(f"!! send {label} -> {delivery.get('state')} {delivery.get('reason') or ''} "
                    f"{row['latency_ms']} ms")
            return row
        time.sleep(0.05)
    row["delivery"] = {"state": "poll_timeout"}
    console(f"!! send {label} -> poll_timeout")
    return row


class Console:
    """Timestamped capture of the reference console on an already-open port."""

    def __init__(self, stream: serial.Serial, path: pathlib.Path):
        self.stream = stream
        self.log = path.open("w", encoding="utf-8")
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def note(self, text: str) -> None:
        with self.lock:
            self.log.write(f"[{stamp()}] {text}\n")
            self.log.flush()

    def run(self) -> None:
        buffer = b""
        while not self.stop.is_set():
            try:
                data = self.stream.read(4096)
            except (OSError, serial.SerialException) as exc:
                self.note(f"!! serial error: {exc}")
                time.sleep(0.2)
                continue
            if not data:
                continue
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                with self.lock:
                    self.log.write(f"[{stamp()}] {line.decode('utf-8', 'replace').rstrip()}\n")
                    self.log.flush()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        self.log.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rig", required=True)
    parser.add_argument("--bench", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--ctl", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--destination", type=int, required=True)
    parser.add_argument("--cycles", type=int, default=10)
    parser.add_argument("--sends", type=int, default=10)
    parser.add_argument("--baseline", type=int, default=3)
    parser.add_argument("--hold-s", type=float, default=0.5)
    parser.add_argument("--send-gap-s", type=float, default=1.0)
    parser.add_argument("--poll-timeout-s", type=float, default=9.0)
    parser.add_argument("--cycle-gap-s", type=float, default=2.0)
    parser.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args()
    if args.hold_s < 0.1 or args.cycles < 1 or args.sends < 1:
        parser.error("hold-s >= 0.1, cycles >= 1, sends >= 1")
    board = rig.load_rigs(args.rig)[args.bench].boards[args.board]
    if board.role != "reference" or board.chip not in ("esp32c3", "esp32c5", "esp32c6") or not board.mac:
        parser.error("reset requires a pinned C3/C5/C6 reference board")
    port, _, status = rig.resolve_board_port(board)
    if status != "ONLINE" or port is None:
        parser.error(f"target port unavailable: {status}")
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    identity = flash.preflight_board(board, port, flash.DEFAULT_ESPTOOL, str(out))
    base = [args.ctl, "--socket", args.socket]
    record = {"board": args.board, "identity": identity, "port": port,
              "destination": args.destination, "cycles": args.cycles, "sends": args.sends,
              "hold_s": args.hold_s, "send_gap_s": args.send_gap_s,
              "started_unix": time.time(), "baseline": [], "cycle_results": []}
    device = serial.Serial(port=None, baudrate=115200, timeout=0.1)
    device.dtr = True   # USB Serial/JTAG console emits only with DTR asserted
    device.rts = False
    device.port = port
    device.open()
    console = Console(device, out / "console.log")
    console.note(f"!! preflight {identity}")
    time.sleep(1.0)
    try:
        for i in range(args.baseline):
            record["baseline"].append(
                probe(base, args.destination, f"B{i}", time.monotonic() + 30,
                      args.poll_timeout_s, console.note))
            time.sleep(args.send_gap_s)
        for cycle in range(args.cycles):
            device.dtr = False
            device.rts = True
            held = time.monotonic()
            console.note(f"!! cycle {cycle} reset assert (RTS, DTR low)")
            time.sleep(args.hold_s)
            device.rts = False
            device.dtr = True
            released = time.monotonic()
            console.note(f"!! cycle {cycle} reset released after {released - held:.3f}s")
            result = {"cycle": cycle, "released_unix": time.time(),
                      "actual_hold_s": round(released - held, 3), "sends": [],
                      "recovery_s": None}
            for i in range(args.sends):
                row = probe(base, args.destination, f"C{cycle}-{i}", time.monotonic() + 30,
                            args.poll_timeout_s, console.note)
                row["offset_s"] = round(time.monotonic() - released, 3)
                result["sends"].append(row)
                if (result["recovery_s"] is None and
                        row.get("delivery", {}).get("state") == "delivered"):
                    result["recovery_s"] = round(
                        time.monotonic() - released - row["latency_ms"] / 1000, 3)
                time.sleep(args.send_gap_s)
            result["delivered"] = sum(
                1 for r in result["sends"] if r.get("delivery", {}).get("state") == "delivered")
            result["idempotency_full"] = sum(
                1 for r in result["sends"]
                if "IDEMPOTENCY_FULL" in str(r.get("response", {}).get("error", "")))
            try:
                result["events_tail"] = ctl(base, "events")
            except Exception as exc:  # noqa: BLE001 - evidence only
                result["events_tail"] = {"error": str(exc)}
            record["cycle_results"].append(result)
            console.note(f"!! cycle {cycle} delivered {result['delivered']}/{args.sends} "
                         f"recovery_s={result['recovery_s']}")
            time.sleep(args.cycle_gap_s)
    finally:
        console.note("!! run finished")
        console.close()
        device.close()
    record["finished_unix"] = time.time()
    # A reboot that logs BOOT_HEAP_BELOW_FLOOR (or a Wi-Fi/PHY allocation
    # failure) is a failed start even if delivery later recovers (issue #166).
    boot_failures = flash.boot_log_failures(
        (out / "console.log").read_text(encoding="utf-8", errors="replace"))
    record["boot_failure_lines"] = boot_failures[:20]
    delivered = [c["delivered"] for c in record["cycle_results"]]
    recoveries = [c["recovery_s"] for c in record["cycle_results"] if c["recovery_s"] is not None]
    record["summary"] = {
        "baseline_delivered": sum(
            1 for r in record["baseline"] if r.get("delivery", {}).get("state") == "delivered"),
        "baseline_sends": len(record["baseline"]),
        "cycles": args.cycles,
        "sends_per_cycle": args.sends,
        "delivered_total": sum(delivered),
        "delivered_per_cycle": delivered,
        "cycles_recovered": len(recoveries),
        "recovery_s_min": min(recoveries) if recoveries else None,
        "recovery_s_max": max(recoveries) if recoveries else None,
        "recovery_s_median": sorted(recoveries)[len(recoveries) // 2] if recoveries else None,
        "idempotency_full_total": sum(c["idempotency_full"] for c in record["cycle_results"]),
        "boot_failures": len(boot_failures),
    }
    (out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record["summary"]))
    return (0 if record["summary"]["cycles_recovered"] == args.cycles and not boot_failures
            else 1)


if __name__ == "__main__":
    raise SystemExit(main())
