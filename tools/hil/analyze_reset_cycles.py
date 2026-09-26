#!/usr/bin/env python3
"""Summarize reference reset 10×10 delivery and recovery evidence."""

import argparse
import json
import pathlib
import re
import statistics


BOOT = re.compile(r"dev adopted \(node 0x[0-9a-f]+, boot (\d+)\)")


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    at = (len(ordered) - 1) * fraction
    low = int(at)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (at - low), 2)


def health(path: pathlib.Path, node: str) -> dict:
    samples = 0
    auth = 0
    route_up = 0
    errors = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        samples += 1
        session = row.get("adapter", {}).get("session", {})
        auth += session.get("authenticated") is True
        errors = max(errors, row.get("adapter", {}).get("protocol_errors") or 0)
        nodes = row.get("nodes", {}).get("result", {}).get("nodes", [])
        route_up += any(item.get("node") == node and item.get("connected") and
                        item.get("next_hop") is not None and
                        item.get("route_metric") is not None for item in nodes)
    return {"samples": samples, "authenticated": auth,
            "protocol_errors_max": errors, "route_up": route_up,
            "route_down": samples - route_up}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=pathlib.Path, required=True)
    parser.add_argument("--console", type=pathlib.Path)
    parser.add_argument("--health", type=pathlib.Path)
    parser.add_argument("--route-node", type=int)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.result.read_text())
    cycles = record["cycle_results"]
    sends = [row for cycle in cycles for row in cycle["sends"]]
    success = [row for row in sends if row.get("delivery", {}).get("state") == "delivered"]
    latencies = [row["latency_ms"] for row in success if "latency_ms" in row]
    reasons = {}
    for row in sends:
        delivery = row.get("delivery", {})
        key = delivery.get("reason") or delivery.get("state") or "unknown"
        reasons[key] = reasons.get(key, 0) + 1
    recoveries = [cycle["recovery_s"] for cycle in cycles
                  if cycle.get("recovery_s") is not None]
    result = {"cycles": len(cycles), "sends_per_cycle": record["sends"],
              "baseline_delivered": record["summary"]["baseline_delivered"],
              "baseline_sends": record["summary"]["baseline_sends"],
              "delivered_per_cycle": [cycle["delivered"] for cycle in cycles],
              "attempted": len(sends), "delivered": len(success), "reasons": reasons,
              "success_latency_ms": {"median": round(statistics.median(latencies), 2)
                                     if latencies else None,
                                     "p95": percentile(latencies, 0.95),
                                     "max": max(latencies) if latencies else None},
              "recovery_s": {"min": min(recoveries) if recoveries else None,
                             "median": statistics.median(recoveries) if recoveries else None,
                             "max": max(recoveries) if recoveries else None},
              "boot_failures_recorded": record["summary"]["boot_failures"]}
    console = args.console or args.result.with_name("console.log")
    lines = console.read_text(encoding="utf-8", errors="replace").splitlines()
    boots = [int(found.group(1)) for line in lines if (found := BOOT.search(line))]
    result["console"] = {"boot_ids": boots,
                         "boot_strictly_increasing": len(boots) >= len(cycles) and
                         all(b > a for a, b in zip(boots, boots[1:])),
                         "boot_heap_below_floor": sum("BOOT_HEAP_BELOW_FLOOR" in line
                                                      for line in lines),
                         "peer_not_found": sum("ESP-NOW peer not found" in line
                                               for line in lines),
                         "peer_exists": sum("Peer exists" in line for line in lines),
                         "stale_events": sum("discovery event=STALE" in line for line in lines)}
    if args.health and args.route_node:
        result["host_health"] = health(args.health, f"{args.route_node:016x}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"attempted": result["attempted"], "delivered": result["delivered"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
