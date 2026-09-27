#!/usr/bin/env python3
"""Build the 25 firmware cells in .github/workflows/sdk.yml for HIL review.

The machine-local ``routeloom-idf-build --matrix`` predates the current CI
matrix and still tries to build the removed bench_node app. This runner uses
the pinned HIL container builder and records each real CI cell separately.
Images stay in the local ignored build directory; the JSON result contains no
firmware binaries or development credentials.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import fcntl
import json
import pathlib
import subprocess
import time


ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD = ROOT / "tools/hil/build_image.sh"


def cells() -> list[tuple[str, str, str, list[str]]]:
    rows = []
    for target in ("esp32c3", "esp32s3", "esp32c5"):
        for app in ("reference_node", "bridge_node"):
            rows.append((app, target, "normal", []))
        rows.append(("reference_node", target, "legacy-sleep", [
            "CONFIG_ROUTELOOM_DEEP_SLEEP=y",
            "CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE=y",
        ]))
    c3 = "esp32c3"
    legacy = "CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE=y"
    member = "CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y"
    rows += [
        ("bridge_node", c3, "observe", [legacy, "CONFIG_ROUTELOOM_DISCOVERY=y",
                                        "CONFIG_ROUTELOOM_MIGRATION=1"]),
        ("bridge_node", c3, "endpoints", [legacy, "CONFIG_ROUTELOOM_CAPABILITY=0x1f"]),
        ("reference_node", c3, "config", [legacy, "CONFIG_ROUTELOOM_CONFIG=y"]),
        ("reference_node", c3, "maintenance", ["CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y"]),
        ("bridge_node", c3, "maintenance", [legacy, "CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y"]),
        ("reference_node", c3, "route-scoped", [legacy,
            "CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED=y"]),
        ("bridge_node", c3, "route-scoped", [legacy,
            "CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED=y"]),
    ]
    for target in ("esp32c3", "esp32s3", "esp32c5"):
        for app in ("reference_node", "bridge_node"):
            rows.append((app, target, "member", [member]))
    rows += [
        ("reference_node", c3, "member-sleep", [member, "CONFIG_ROUTELOOM_DEEP_SLEEP=y"]),
        ("bridge_node", c3, "paired", [legacy, "CONFIG_ROUTELOOM_DISCOVERY=y",
            "CONFIG_ROUTELOOM_CAPABILITY=0x1f", "CONFIG_ROUTELOOM_NODE_ID=0x1",
            "CONFIG_ROUTELOOM_PEER_NODE_ID=0x2",
            'CONFIG_ROUTELOOM_PEER_MAC="94:a9:90:7a:b5:60"']),
        ("reference_node", c3, "paired", [legacy, "CONFIG_ROUTELOOM_DISCOVERY=y",
            "CONFIG_ROUTELOOM_CONFIG=y", "CONFIG_ROUTELOOM_NODE_ID=0x2",
            "CONFIG_ROUTELOOM_PEER_NODE_ID=0x1",
            'CONFIG_ROUTELOOM_PEER_MAC="94:a9:90:6a:ee:c4"']),
    ]
    assert len(rows) == 25
    return rows


def build(index: int, cell: tuple[str, str, str, list[str]], prefix: str) -> dict:
    app, target, profile, options = cell
    label = f"{prefix}-{index:02d}-{app}-{target}-{profile}"
    # Share the local wrapper's three-container cap with other worktrees.
    while True:
        for slot in range(3):
            lock = pathlib.Path(f"/tmp/routeloom-idf-build.slot{slot}").open("w")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                lock.close()
                continue
            try:
                result = subprocess.run([str(BUILD), app, target, label, *options],
                                        cwd=ROOT, capture_output=True, text=True)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                lock.close()
            break
        else:
            time.sleep(2)
            continue
        break
    image = ROOT / "artifacts/hil/2026-09-26/images" / label
    ram = image / "build/ram-report.json"
    return {"index": index, "label": label, "app": app, "target": target,
            "profile": profile, "options": options, "exit_code": result.returncode,
            "stdout": result.stdout.strip(), "stderr": result.stderr.strip(),
            "build_log": str((image / "build.log").relative_to(ROOT)),
            "ram_report": str(ram.relative_to(ROOT)) if ram.exists() else None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--label-prefix", default="full-r9-ci")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.jobs not in (1, 2, 3) or not args.label_prefix.startswith("full-r"):
        parser.error("jobs must be 1..3 and labels must start full-r")
    planned = cells()
    if args.dry_run:
        print(json.dumps([{"index": i, "app": app, "target": target,
                           "profile": profile, "options": options}
                          for i, (app, target, profile, options) in enumerate(planned)], indent=2))
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(build, i, cell, args.label_prefix): i
                   for i, cell in enumerate(planned)}
        for future in as_completed(futures):
            row = future.result()
            results.append(row)
            print(f"[{len(results)}/25] {row['label']} exit={row['exit_code']}", flush=True)
            args.out.write_text(json.dumps({"timestamp_utc": datetime.datetime.now(
                datetime.timezone.utc).isoformat(), "expected": 25,
                "completed": len(results), "passed": sum(r["exit_code"] == 0 for r in results),
                "results": sorted(results, key=lambda r: r["index"])}, indent=2) + "\n")
    return 0 if all(row["exit_code"] == 0 for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
