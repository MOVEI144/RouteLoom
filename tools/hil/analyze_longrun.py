#!/usr/bin/env python3
"""Summarize a live HIL traffic run, route snapshots, and console heap samples."""

import argparse
import json
import pathlib
import re
import statistics


HEAP = re.compile(r"HIL HEAP free=(\d+) largest=(\d+) min=(\d+) B")
BOOT = re.compile(r"dev adopted \(node 0x[0-9a-f]+, boot (\d+)\)")
STACK = re.compile(r"stack hwm (\S+) (\d+) B")


def rows(path: pathlib.Path) -> list[dict]:
    result = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # A still-running writer may leave one partial final line.
    return result


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    at = (len(ordered) - 1) * fraction
    low = int(at)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (at - low), 2)


def traffic_summary(records: list[dict]) -> dict:
    by_destination = {}
    for record in records:
        destination = str(record.get("destination"))
        by_destination.setdefault(destination, []).append(record)

    def summarize(items: list[dict]) -> dict:
        delivered = [item for item in items if item.get("delivery", {}).get("state") == "delivered"]
        latencies = [item["latency_ms"] for item in delivered if "latency_ms" in item]
        reasons = {}
        for item in items:
            delivery = item.get("delivery", {})
            key = f"{delivery.get('state', 'none')}:{delivery.get('reason', 'none')}"
            reasons[key] = reasons.get(key, 0) + 1
        return {"accepted": len(items), "delivered": len(delivered),
                "success_rate": round(len(delivered) / len(items), 4) if items else None,
                "latency_ms_median": round(statistics.median(latencies), 2) if latencies else None,
                "latency_ms_p95": percentile(latencies, 0.95),
                "latency_ms_max": max(latencies) if latencies else None,
                "outcomes": reasons}

    started = records[0].get("admitted_at_unix") if records else None
    last = records[-1].get("admitted_at_unix") if records else None
    return {"all": summarize(records),
            "by_destination": {node: summarize(items) for node, items in by_destination.items()},
            "admission_retries": sum(max(0, item.get("admission_attempts", 1) - 1)
                                     for item in records),
            "first_admitted_unix": started, "last_admitted_unix": last,
            "admission_span_s": round(last - started, 2) if started is not None and last is not None else None}


def health_summary(records: list[dict], destinations: set[str]) -> dict:
    route_counts = {node: 0 for node in destinations}
    rssi = {node: [] for node in destinations}
    authenticated = 0
    sessions = set()
    bridge_boots = set()
    protocol_errors = 0
    events = {}
    seen_event_ids = set()
    for sample in records:
        adapter = sample.get("adapter", {})
        session = adapter.get("session", {})
        if session.get("authenticated"):
            authenticated += 1
            sessions.add(session.get("id"))
            if session.get("boot") is not None:
                bridge_boots.add(session["boot"])
        protocol_errors = max(protocol_errors, adapter.get("protocol_errors") or 0)
        nodes = sample.get("nodes", {}).get("result", {}).get("nodes", [])
        for node in nodes:
            if node.get("node") in route_counts and node.get("connected") and (
                node.get("hops") is not None or
                (node.get("next_hop") is not None and node.get("route_metric") is not None)
            ):
                route_counts[node["node"]] += 1
                if node.get("rssi_dbm") is not None:
                    rssi[node["node"]].append(node["rssi_dbm"])
        for event in sample.get("events", {}).get("events", []):
            key = (session.get("id"), event.get("seq"))
            if key in seen_event_ids:
                continue
            seen_event_ids.add(key)
            kind = str(event.get("kind"))
            events[kind] = events.get(kind, 0) + 1
    return {"samples": len(records), "authenticated_samples": authenticated,
            "bridge_sessions": len(sessions), "bridge_boots_seen": sorted(bridge_boots),
            "max_protocol_errors": protocol_errors,
            "route_samples_by_destination": route_counts,
            "rssi_dbm_by_destination": {
                node: {"samples": len(values), "min": min(values),
                       "median": statistics.median(values), "max": max(values)}
                for node, values in rssi.items() if values},
            "event_kinds": events,
            "observation_span_s": round(records[-1]["elapsed_s"] - records[0]["elapsed_s"], 2)
            if len(records) > 1 else 0}


def console_summary(path: pathlib.Path) -> dict:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    heaps = [tuple(map(int, found.groups())) for line in lines
             if (found := HEAP.search(line))]
    boots = {int(found.group(1)) for line in lines if (found := BOOT.search(line))}
    stack_min = {}
    for line in lines:
        if found := STACK.search(line):
            name, value = found.group(1), int(found.group(2))
            stack_min[name] = min(value, stack_min.get(name, value))
    result = {"heap_samples": len(heaps), "boot_ids_seen": sorted(boots),
              "stack_min_remaining_b": stack_min,
              "stale_events": sum("discovery event=STALE" in line for line in lines),
              "boot_heap_below_floor": sum("BOOT_HEAP_BELOW_FLOOR" in line for line in lines),
              "usb_connects": sum("!! connected " in line for line in lines),
              "usb_disconnects": sum("!! disconnected:" in line for line in lines)}
    if heaps:
        result.update({"first_free_b": heaps[0][0], "last_free_b": heaps[-1][0],
                       "free_delta_b": heaps[-1][0] - heaps[0][0],
                       "minimum_free_b": min(sample[0] for sample in heaps),
                       "first_largest_b": heaps[0][1], "last_largest_b": heaps[-1][1],
                       "largest_delta_b": heaps[-1][1] - heaps[0][1],
                       "minimum_largest_b": min(sample[1] for sample in heaps),
                       "minimum_ever_free_b": min(sample[2] for sample in heaps)})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traffic", type=pathlib.Path, required=True)
    parser.add_argument("--health", type=pathlib.Path, required=True)
    parser.add_argument("--console", nargs=2, action="append", metavar=("NODE", "PATH"),
                        default=[])
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    traffic = traffic_summary(rows(args.traffic))
    destinations = {f"{int(node):016x}" for node in traffic["by_destination"]}
    summary = {"traffic": traffic, "health": health_summary(rows(args.health), destinations),
               "console": {node: console_summary(pathlib.Path(path))
                           for node, path in args.console}}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"accepted": traffic["all"]["accepted"],
                      "delivered": traffic["all"]["delivered"],
                      "health_samples": summary["health"]["samples"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
