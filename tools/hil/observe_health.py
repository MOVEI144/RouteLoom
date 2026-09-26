#!/usr/bin/env python3
"""Record live adapter, route, and event snapshots during a long HIL run."""

import argparse
import datetime
import json
import pathlib
import subprocess
import time


def query(base: list[str], method: str) -> dict:
    run = subprocess.run(base + [method], capture_output=True, text=True, timeout=10)
    if run.returncode:
        return {"error": (run.stderr or run.stdout).strip()}
    return json.loads(run.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ctl", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--seconds", type=float, default=3600)
    parser.add_argument("--poll-s", type=float, default=30)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.seconds <= 0 or args.poll_s <= 0:
        parser.error("seconds and poll-s must be positive")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    base = [args.ctl, "--socket", args.socket]
    started = time.monotonic()
    sample = 0
    with args.out.open("w", encoding="utf-8") as log:
        while time.monotonic() - started < args.seconds:
            record = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(
                          timespec="milliseconds"),
                      "elapsed_s": round(time.monotonic() - started, 2)}
            for method in ("adapter", "nodes", "events"):
                try:
                    record[method] = query(base, method)
                except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                    record[method] = {"error": str(exc)}
            log.write(json.dumps(record, separators=(",", ":")) + "\n")
            log.flush()
            sample += 1
            time.sleep(max(0, started + sample * args.poll_s - time.monotonic()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
