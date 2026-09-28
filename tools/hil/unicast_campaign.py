#!/usr/bin/env python3
"""Run paced 100-send HIL campaigns, rebooting the pinned gateway between targets.

The gateway's bounded idempotency history holds 112 distinct identities per
boot. One campaign uses one boot so the measurements stay below that limit.
"""

import argparse
import datetime
import json
import pathlib
import subprocess
import sys
import time

import flash
import rig


def stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rig", required=True)
    p.add_argument("--bench", required=True)
    p.add_argument("--bridge", default="bridge")
    p.add_argument("--destinations", nargs="+", type=int, required=True)
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--daemon", required=True)
    p.add_argument("--ctl", required=True)
    p.add_argument("--acl", required=True)
    p.add_argument("--socket", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--settle-s", type=float, default=15)
    p.add_argument("--daemon-arg", action="append", default=[],
                   help="extra daemon argument (repeatable), e.g. --daemon-arg=--usb-dev-secret-file")
    args = p.parse_args()
    if args.count < 1 or args.count > 100 or args.settle_s < 0:
        p.error("count must be 1..100 and settle-s nonnegative")
    board = rig.load_rigs(args.rig)[args.bench].boards[args.bridge]
    if board.role != "bridge" or board.app != "bridge_node" or not board.mac:
        p.error("bridge must be a chip/MAC-pinned bridge_node")
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for cycle, destination in enumerate(args.destinations):
        target_dir = out / f"cycle-{cycle:02d}-node{destination}"
        target_dir.mkdir(exist_ok=True)
        port, _, state = rig.resolve_board_port(board)
        if state != "ONLINE" or port is None:
            rows.append({"destination": destination, "error": f"bridge {state}"})
            continue
        # Every reboot is a real chip/MAC and secure-state preflight, which
        # also reboots this board through the ROM and clears its RAM table.
        identity = flash.preflight_board(board, port, flash.DEFAULT_ESPTOOL,
                                         str(target_dir))
        port, _, state = rig.resolve_board_port(board)
        if state != "ONLINE" or port is None:
            rows.append({"destination": destination, "error": f"bridge after reset {state}"})
            continue
        started = stamp()
        with (target_dir / "daemon.log").open("w") as daemon_log:
            auth_started = time.monotonic()
            daemon = subprocess.Popen(
                [args.daemon, "--socket", args.socket, "--device", port,
                 "--api-acl-file", args.acl, *args.daemon_arg], stdout=daemon_log,
                stderr=subprocess.STDOUT)
            try:
                ready = False
                for _ in range(90):
                    if daemon.poll() is not None:
                        break
                    try:
                        result = subprocess.run(
                            [args.ctl, "--socket", args.socket, "adapter"],
                            capture_output=True, text=True, timeout=5)
                        ready = (result.returncode == 0 and
                                 json.loads(result.stdout).get("session", {}).get(
                                     "authenticated") is True)
                    except (subprocess.TimeoutExpired, ValueError):
                        pass
                    if ready:
                        break
                    time.sleep(0.5)
                if not ready:
                    rows.append({"destination": destination,
                                 "error": "daemon authentication timeout",
                                 "identity": identity, "started": started})
                    continue
                auth_s = round(time.monotonic() - auth_started, 3)
                time.sleep(args.settle_s)
                with (target_dir / "runner.log").open("w") as runner_log:
                    run = subprocess.run(
                        [sys.executable, str(pathlib.Path(__file__).with_name(
                            "accepted_traffic.py")), "--ctl", args.ctl,
                         "--socket", args.socket, "--destinations", str(destination),
                         "--count", str(args.count), "--timeout-s", "3600",
                         "--out", str(target_dir / "traffic.jsonl")],
                        stdout=runner_log, stderr=subprocess.STDOUT, timeout=4200)
                summary = target_dir / "traffic.summary.json"
                rows.append({"destination": destination, "identity": identity,
                             "started": started, "finished": stamp(),
                             "adapter_auth_s": auth_s,
                             "runner_exit": run.returncode,
                             "summary": json.loads(summary.read_text())
                             if summary.is_file() else None})
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)
            (out / "campaign.json").write_text(json.dumps(rows, indent=2) + "\n")
    (out / "campaign.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps(rows))
    return 0 if len(rows) == len(args.destinations) and all(
        row.get("runner_exit") == 0 for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
