#!/usr/bin/env python3
"""Measure accepted legacy sends, respecting the host admission limit."""

import argparse
import json
import pathlib
import re
import statistics
import subprocess
import time


TERMINAL = {"delivered", "expired", "failed", "rejected", "cancelled"}


def command(base: list[str], *args: str) -> dict:
    run = subprocess.run(base + list(args), capture_output=True, text=True, timeout=12)
    if run.returncode:
        raise RuntimeError(f"{' '.join(args)}: {run.stderr or run.stdout}")
    return json.loads(run.stdout)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (position - low), 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ctl", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--destinations", type=int, nargs="+", required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--timeout-s", type=float, default=1800)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.count < 1 or args.count > 1000 or args.timeout_s <= 0:
        parser.error("count must be 1..1000 and timeout must be positive")
    base = [args.ctl, "--socket", args.socket]
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + args.timeout_s
    rows = []
    limited = 0
    stopped_reason = None
    started = time.time()
    with out.open("w", encoding="utf-8") as log:
        for index in range(args.count):
            node = args.destinations[index % len(args.destinations)]
            payload = b"R2HIL" + index.to_bytes(4, "big")
            attempts = 0
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"stopped after {len(rows)} accepted sends")
                attempts += 1
                reply = command(base, "send", str(node), payload.hex())
                if reply.get("accepted"):
                    break
                error = str(reply.get("error", ""))
                retry = re.search(r"rate limited .* retry in (\d+) ms", error)
                if retry is None:
                    raise RuntimeError(f"send to {node} refused: {reply}")
                limited += 1
                time.sleep(min(max(int(retry.group(1)) / 1000 + 0.1, 0.1), 12))
            admitted = time.monotonic()
            request = reply["request"]
            row = {"index": index, "destination": node, "request": request,
                   "admitted_at_unix": time.time(), "admission_attempts": attempts}
            while time.monotonic() - admitted < 9:
                delivery = next((x for x in command(base, "deliveries").get("deliveries", [])
                                 if x.get("request") == request), None)
                if delivery and delivery.get("state") in TERMINAL:
                    row["delivery"] = delivery
                    row["latency_ms"] = round((time.monotonic() - admitted) * 1000, 2)
                    break
                time.sleep(0.05)
            else:
                row["delivery"] = {"state": "poll_timeout"}
            rows.append(row)
            log.write(json.dumps(row, separators=(",", ":")) + "\n")
            log.flush()
            if (index + 1) % 10 == 0:
                print(f"accepted={index + 1} delivered="
                      f"{sum(x['delivery']['state'] == 'delivered' for x in rows)}",
                      flush=True)
            if row["delivery"].get("reason") == "IDEMPOTENCY_FULL":
                stopped_reason = "device idempotency table full"
                break
    latencies = [r["latency_ms"] for r in rows
                 if r["delivery"]["state"] == "delivered"]
    summary = {"requested": args.count, "host_accepted": len(rows),
               "delivered": len(latencies), "stopped_reason": stopped_reason,
               "success_rate": len(latencies) / len(rows),
               "rate_limit_retries": limited, "elapsed_s": round(time.time() - started, 2),
               "latency_ms_median": statistics.median(latencies) if latencies else None,
               "latency_ms_p95": percentile(latencies, 0.95),
               "latency_ms_max": max(latencies) if latencies else None,
               "by_destination": {
                   str(node): {"accepted": sum(r["destination"] == node for r in rows),
                               "delivered": sum(r["destination"] == node and
                                                r["delivery"]["state"] == "delivered"
                                                for r in rows)}
                   for node in args.destinations},
               "evidence": str(out)}
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, separators=(",", ":")), flush=True)
    return 0 if stopped_reason is None and len(latencies) == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
