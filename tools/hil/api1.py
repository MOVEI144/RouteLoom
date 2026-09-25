#!/usr/bin/env python3
"""Send one API1 request to a local RouteLoom daemon Unix socket."""

import argparse
import json
import os
import socket
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("method")
    parser.add_argument("params", nargs="?", default="{}", help="JSON object")
    args = parser.parse_args()
    params = json.loads(args.params)
    if not isinstance(params, dict):
        parser.error("params must be a JSON object")
    request = {
        "v": 1,
        "request_id": f"hil-{os.getpid()}-{time.time_ns()}",
        "method": args.method,
        "params": params,
    }
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect(args.socket)
        conn.sendall(b"API1 " + json.dumps(request, separators=(",", ":")).encode() + b"\n")
        with conn.makefile("rb") as source:
            line = source.readline()
    if not line:
        raise RuntimeError("daemon closed without an API1 response")
    print(line.decode().rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
