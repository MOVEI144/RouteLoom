#!/usr/bin/env python3
"""Measure gateway authentication and live node-route convergence in HIL."""

import argparse
import json
import pathlib
import subprocess
import time


def query(ctl: str, socket: str, method: str) -> dict:
    result = subprocess.run([ctl, "--socket", socket, method], capture_output=True,
                            text=True, timeout=8)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return json.loads(result.stdout)


def has_route(row: dict) -> bool:
    """Host nodes leaves hops null for a learned, non-neighbor route."""
    return bool(row.get("connected") and
                (row.get("hops") is not None or
                 (row.get("next_hop") is not None and
                  row.get("route_metric") is not None)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ctl", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--nodes", type=int, nargs="+", required=True)
    parser.add_argument("--seconds", type=float, default=90)
    parser.add_argument("--poll-s", type=float, default=0.25)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.seconds <= 0 or args.poll_s <= 0:
        parser.error("seconds and poll-s must be positive")
    expected = {f"{node:016x}" for node in args.nodes}
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    first_auth = None
    first_routes = {}
    last_signature = None
    last_error = None
    with out.open("w", encoding="utf-8") as log:
        while time.monotonic() - start < args.seconds:
            elapsed = round(time.monotonic() - start, 3)
            try:
                adapter = query(args.ctl, args.socket, "adapter")
                if adapter.get("session", {}).get("authenticated") is True and first_auth is None:
                    first_auth = elapsed
                    log.write(json.dumps({"elapsed_s": elapsed, "kind": "authenticated",
                                          "adapter": adapter}) + "\n")
                nodes_reply = query(args.ctl, args.socket, "nodes")
                result = nodes_reply.get("result", {})
                nodes = result.get("nodes", [])
                reachable = {row.get("node") for row in nodes if has_route(row)}
                for node in expected & reachable:
                    first_routes.setdefault(node, elapsed)
                signature = (result.get("source", {}).get("state"),
                             tuple(sorted(reachable & expected)))
                if signature != last_signature:
                    log.write(json.dumps({"elapsed_s": elapsed, "kind": "routes",
                                          "response": nodes_reply}) + "\n")
                    last_signature = signature
                if expected <= reachable:
                    break
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                error = str(exc)
                if error != last_error:
                    log.write(json.dumps({"elapsed_s": elapsed, "kind": "error",
                                          "detail": error}) + "\n")
                    last_error = error
            log.flush()
            time.sleep(args.poll_s)
    summary = {"expected": sorted(expected), "authenticated_at_s": first_auth,
               "routes_at_s": first_routes,
               "all_routes_at_s": max(first_routes.values()) if expected <= first_routes.keys() else None,
               "elapsed_s": round(time.monotonic() - start, 3),
               "source": str(out)}
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 0 if summary["all_routes_at_s"] is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
