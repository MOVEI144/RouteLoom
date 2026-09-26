#!/usr/bin/env python3
"""Summarize opt-in on-device EDHOC timings without copying key material."""

import argparse
import json
import pathlib
import re
import statistics


PRIMITIVE = re.compile(r"HIL EDHOC (ECDH|SIGN|VERIFY) us=(\d+) ok=(\d+)")
HANDSHAKE = re.compile(
    r"HIL EDHOC HANDSHAKE us=(\d+) role=(\d+) scope=(\d+) peer=(\d+) "
    r"heap_free=(\d+) heap_min=(\d+)")
STACK = re.compile(r"stack hwm (\S+) (\d+) B")


def percentile(values: list[int], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    at = (len(ordered) - 1) * fraction
    low = int(at)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (at - low), 2)


def describe(values: list[int]) -> dict:
    return {"count": len(values), "min_us": min(values) if values else None,
            "median_us": statistics.median(values) if values else None,
            "p95_us": percentile(values, 0.95), "max_us": max(values) if values else None}


def analyze(path: pathlib.Path) -> dict:
    primitives = {"ECDH": [], "SIGN": [], "VERIFY": []}
    failures = {key: 0 for key in primitives}
    handshakes = []
    stack_min = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if found := PRIMITIVE.search(line):
            key = found.group(1)
            if found.group(3) == "1":
                primitives[key].append(int(found.group(2)))
            else:
                failures[key] += 1
        if found := HANDSHAKE.search(line):
            handshakes.append({"us": int(found.group(1)), "role": int(found.group(2)),
                               "scope": int(found.group(3)), "peer": int(found.group(4)),
                               "heap_free_b": int(found.group(5)),
                               "heap_min_b": int(found.group(6))})
        if found := STACK.search(line):
            task, remaining = found.group(1), int(found.group(2))
            stack_min[task] = min(remaining, stack_min.get(task, remaining))
    return {"primitive": {key: {**describe(values), "failed": failures[key]}
                          for key, values in primitives.items()},
            "handshake": describe([row["us"] for row in handshakes]),
            "handshake_by_scope": {
                str(scope): describe([row["us"] for row in handshakes
                                      if row["scope"] == scope])
                for scope in sorted({row["scope"] for row in handshakes})},
            "lowest_handshake_heap_free_b": min((row["heap_free_b"] for row in handshakes),
                                                 default=None),
            "lowest_handshake_heap_min_b": min((row["heap_min_b"] for row in handshakes),
                                                default=None),
            "stack_min_remaining_b": stack_min}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console", nargs=2, action="append", metavar=("NODE", "PATH"),
                        required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    summary = {node: analyze(pathlib.Path(path)) for node, path in args.console}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({node: value["handshake"]["count"] for node, value in summary.items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
