#!/usr/bin/env python3
"""Approve one expected real-device Site Authority join request during HIL."""

import argparse
import json
import socket
import time


def call(path: str, method: str, params: dict) -> dict:
    request = {"v": 1, "request_id": f"hil-join-{time.time_ns()}",
               "method": method, "params": params}
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect(path)
        conn.sendall(b"API1 " + json.dumps(request, separators=(",", ":")).encode() + b"\n")
        with conn.makefile("rb") as stream:
            line = stream.readline()
    if not line:
        raise RuntimeError(f"{method}: daemon closed without response")
    response = json.loads(line)
    if not response.get("ok"):
        raise RuntimeError(f"{method}: {response}")
    return response["result"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--device-id", required=True, help="expected 16-hex NodeId")
    parser.add_argument("--role", choices=("endpoint", "relay", "gateway"), required=True)
    parser.add_argument("--timeout-s", type=float, default=60)
    args = parser.parse_args()
    expected = args.device_id.lower().removeprefix("0x").zfill(16)
    deadline = time.monotonic() + args.timeout_s
    while time.monotonic() < deadline:
        result = call(args.socket, "join.requests.list", {})
        for request in result.get("requests", []):
            device = str(request.get("device_id", "")).lower().removeprefix("0x").zfill(16)
            if device != expected or request.get("state") not in ("awaiting", "open", "pending", None):
                continue
            print(json.dumps({"request": request}, sort_keys=True), flush=True)
            decision = call(args.socket, "join.decide", {
                "join_request_id": request["join_request_id"],
                "device_id": expected,
                "verdict": "allow",
                "role": args.role,
                "idempotency_key": f"hil-allow-{request['join_request_id']}",
            })
            print(json.dumps({"decision": decision}, sort_keys=True), flush=True)
            return 0
        time.sleep(0.1)
    print(json.dumps({"error": "request timeout", "device_id": expected}), flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
