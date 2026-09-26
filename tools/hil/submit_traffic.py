#!/usr/bin/env python3
"""Measure API1 submit-to-END_SDK_RECEIVED latency on a live HIL bench."""

import argparse
import json
import os
import pathlib
import re
import statistics
import subprocess
import time


TERMINAL = {"END_SDK_RECEIVED", "EXPIRED_BEFORE_DISPATCH",
            "CANCELLED_BEFORE_DISPATCH", "REJECTED_NOT_ACCEPTED", "TIME_UNCERTAIN"}


def request(base: list[str], args: list[str]) -> dict:
    proc = subprocess.run(base + args, capture_output=True, text=True, timeout=12)
    if proc.returncode:
        raise RuntimeError(f"routeloomctl {args[0]}: {proc.stderr or proc.stdout}")
    return json.loads(proc.stdout)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return round(ordered[lower] +
                 (ordered[upper] - ordered[lower]) * (position - lower), 2)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ctl", required=True)
    p.add_argument("--socket", required=True)
    p.add_argument("--network", required=True)
    p.add_argument("--epoch", required=True)
    p.add_argument("--destination", required=True)
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--timeout-s", type=float, default=35)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    if args.count < 1 or args.count > 1000 or args.timeout_s <= 0:
        p.error("count must be 1..1000 and timeout must be positive")
    base = [args.ctl, "--socket", args.socket]
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with out.open("w", encoding="utf-8") as log:
        for index in range(args.count):
            payload = b"RLSUB" + index.to_bytes(4, "big")
            key = os.urandom(16).hex()
            started = time.monotonic()
            attempts = 0
            while True:
                attempts += 1
                response = request(base, ["submit", "--network", args.network,
                                          "--epoch", args.epoch, "--to", args.destination,
                                          "--payload", payload.hex(), "--key", key,
                                          "--delivery", "RELIABLE", "--storage", "RAM_ONLY",
                                          "--ttl-ms", "30000"])
                if response.get("ok") or time.monotonic() - started > args.timeout_s:
                    break
                error = response.get("error", {})
                if not error.get("retryable"):
                    break
                detail = error.get("detail", {})
                retry_ms = detail.get("retry_after_ms", 1000)
                if not isinstance(retry_ms, int):
                    match = re.search(r"retry in (\d+) ms", str(detail))
                    retry_ms = int(match.group(1)) if match else 1000
                time.sleep(min(max(retry_ms / 1000, 0.1), 10))
            record = {"index": index, "attempts": attempts, "admission": response}
            if response.get("ok"):
                admitted_at = time.monotonic()
                record["admission_wait_ms"] = round((admitted_at - started) * 1000, 2)
                opid = response["result"]["operation_id"]
                deadline = admitted_at + args.timeout_s
                while time.monotonic() < deadline:
                    outcome = request(base, ["operation-get", "--id", opid])
                    if outcome.get("ok") and outcome["result"].get("dispatch_state") in TERMINAL:
                        record["outcome"] = outcome["result"]
                        record["latency_ms"] = round((time.monotonic() - admitted_at) * 1000, 2)
                        break
                    time.sleep(0.05)
                else:
                    record["outcome"] = {"dispatch_state": "POLL_TIMEOUT"}
            records.append(record)
            log.write(json.dumps(record, separators=(",", ":")) + "\n")
            log.flush()
    latencies = [r["latency_ms"] for r in records
                 if r.get("outcome", {}).get("dispatch_state") == "END_SDK_RECEIVED"]
    summary = {"count": args.count,
               "admitted": sum(bool(r["admission"].get("ok")) for r in records),
               "delivered": len(latencies), "success_rate": len(latencies) / args.count,
               "rtt_ms_min": min(latencies) if latencies else None,
               "rtt_ms_median": statistics.median(latencies) if latencies else None,
               "rtt_ms_p95": percentile(latencies, 0.95),
               "rtt_ms_p99": percentile(latencies, 0.99),
               "rtt_ms_max": max(latencies) if latencies else None,
               "evidence": str(out)}
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n",
                                                 encoding="utf-8")
    print(json.dumps(summary, separators=(",", ":")))
    return 0 if len(latencies) == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
