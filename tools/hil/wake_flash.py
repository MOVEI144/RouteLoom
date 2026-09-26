#!/usr/bin/env python3
"""Flash an identified bench board as soon as its deep-sleep USB port returns."""

import argparse
import os
import time

try:
    from . import rig, flash
except ImportError:
    import rig
    import flash


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rig", required=True)
    p.add_argument("--bench", required=True)
    p.add_argument("--board", required=True)
    p.add_argument("--image-dir", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout-s", type=float, default=3600)
    p.add_argument("--capture-boot", action="store_true")
    args = p.parse_args()
    board = rig.load_rigs(args.rig)[args.bench].boards[args.board]
    if board.chip not in ("esp32c3", "esp32c5") or not board.mac:
        p.error("wake flash requires an expected C3/C5 chip and MAC")
    if len(board.port_globs) != 1 or "*" in board.port_globs[0]:
        p.error("wake flash requires one exact by-id port")
    port = board.port_globs[0]
    if board.mac.upper() not in port:
        p.error("by-id path does not contain the expected MAC")
    print(f"waiting for {board.chip}/{board.mac} at {port}", flush=True)
    deadline = time.monotonic() + args.timeout_s
    attempts = 0
    while time.monotonic() < deadline:
        if not os.path.exists(port):
            time.sleep(0.005)
            continue
        attempts += 1
        print(f"port appeared; flash attempt {attempts}", flush=True)
        cmd = ["--rig", args.rig, "--bench", args.bench, "--board", args.board,
               "--image-dir", args.image_dir, "--out", args.out,
               "--boot-seconds", "10" if args.capture_boot else "0"]
        if args.capture_boot:
            cmd.append("--capture-boot")
        try:
            result = flash.main(cmd)
        except flash.FlashError as exc:
            print(f"preflight refused flash: {exc}", flush=True)
        else:
            if result == 0:
                print("flash succeeded", flush=True)
                return 0
            print(f"flash attempt exited {result}", flush=True)
        # A later attempt requires a new USB appearance. This avoids an
        # unbounded write loop if the board stays online with a bad image.
        while os.path.exists(port) and time.monotonic() < deadline:
            time.sleep(0.2)
    print("timed out waiting for a flashable USB appearance", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
