#!/usr/bin/env python3
"""Measure real host-to-reference delivery through a running HIL daemon."""

import argparse
import json
import pathlib
import statistics
import subprocess
import time


TERMINAL = {"delivered", "expired", "failed", "rejected", "cancelled"}


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return round(ordered[lower] +
                 (ordered[upper] - ordered[lower]) * (position - lower), 2)


def ctl(base: list[str], args: list[str]) -> dict:
    result = subprocess.run(base + args, capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise RuntimeError(f"routeloomctl {args[0]}: {result.stderr or result.stdout}")
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ctl", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--destination", type=int, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--timeout-s", type=float, default=15)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.count < 1 or args.count > 1000 or args.timeout_s <= 0:
        parser.error("count must be 1..1000 and timeout must be positive")
    base = [args.ctl, "--socket", args.socket]
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with path.open("w", encoding="utf-8") as log:
        for index in range(args.count):
            payload = b"RLHIL" + index.to_bytes(4, "big")
            started = time.monotonic()
            response = ctl(base, ["send", str(args.destination), payload.hex()])
            record = {"index": index, "accepted": response.get("accepted", False),
                      "request": response.get("request"), "response": response}
            if response.get("accepted"):
                deadline = started + args.timeout_s
                while time.monotonic() < deadline:
                    snapshot = ctl(base, ["deliveries"])
                    matches = [d for d in snapshot.get("deliveries", [])
                               if d.get("request") == response["request"]]
                    if matches and matches[0].get("state") in TERMINAL:
                        record["delivery"] = matches[0]
                        record["latency_ms"] = round((time.monotonic() - started) * 1000, 2)
                        break
                    time.sleep(0.05)
                else:
                    record["delivery"] = {"state": "timeout"}
            records.append(record)
            log.write(json.dumps(record, separators=(",", ":")) + "\n")
            log.flush()
    delivered = [r["latency_ms"] for r in records
                 if r.get("delivery", {}).get("state") == "delivered"]
    summary = {"count": args.count, "accepted": sum(r["accepted"] for r in records),
               "delivered": len(delivered),
               "success_rate": len(delivered) / args.count,
               "rtt_ms_min": min(delivered) if delivered else None,
               "rtt_ms_median": statistics.median(delivered) if delivered else None,
               "rtt_ms_p95": percentile(delivered, 0.95),
               "rtt_ms_p99": percentile(delivered, 0.99),
               "rtt_ms_max": max(delivered) if delivered else None,
               "evidence": str(path)}
    summary_path = path.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, separators=(",", ":")))
    return 0 if len(delivered) == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
