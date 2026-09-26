#!/usr/bin/env python3
"""Record read-only Site Authority state during MemberEdhoc HIL tests."""

import argparse
import datetime
import json
import pathlib
import socket
import time


def call(path: str, method: str, params: dict) -> dict:
    request = {"v": 1, "request_id": f"hil-site-watch-{time.time_ns()}",
               "method": method, "params": params}
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect(path)
        conn.sendall(b"API1 " + json.dumps(request, separators=(",", ":")).encode() + b"\n")
        with conn.makefile("rb") as source:
            line = source.readline()
    if not line:
        raise RuntimeError(f"{method}: no response")
    return json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--poll-s", type=float, default=5)
    parser.add_argument("--operation-id", action="append", default=[])
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.seconds <= 0 or args.poll_s <= 0:
        parser.error("seconds and poll-s must be positive")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    sample = 0
    with args.out.open("w", encoding="utf-8", buffering=1) as log:
        while time.monotonic() - started < args.seconds:
            record = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(
                          timespec="milliseconds"),
                      "elapsed_s": round(time.monotonic() - started, 2)}
            for method, params in (("site.status", {}), ("members.list", {}),
                                   ("group_keys.status", {})):
                try:
                    record[method] = call(args.socket, method, params)
                except (OSError, ValueError, RuntimeError) as exc:
                    record[method] = {"error": str(exc)}
            for operation_id in args.operation_id:
                try:
                    record.setdefault("operations", {})[operation_id] = call(
                        args.socket, "operations.get", {"operation_id": operation_id})
                except (OSError, ValueError, RuntimeError) as exc:
                    record.setdefault("operations", {})[operation_id] = {"error": str(exc)}
            log.write(json.dumps(record, separators=(",", ":")) + "\n")
            sample += 1
            time.sleep(max(0, started + sample * args.poll_s - time.monotonic()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
