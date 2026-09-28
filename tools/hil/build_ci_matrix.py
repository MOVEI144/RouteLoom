#!/usr/bin/env python3
"""Build the firmware cells of tools/ci/cells.json (the sdk.yml matrix) for HIL review.

This runner uses the pinned HIL container builder and records each CI cell
separately, with the cell's sdkconfig overlay. Bundles stay in the local
ignored images directory; the JSON result contains no firmware binaries or
development credentials.
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
CELLS = ROOT / "tools/ci/cells.json"


def cells() -> list[tuple[str, str, str, list[str]]]:
    """(app, target, cell id, sdkconfig overlay) for every CI cell."""
    data = json.loads(CELLS.read_text(encoding="utf-8"))
    return [(c["app"], c["target"], c["id"], list(c["overlay"])) for c in data["cells"]]


def build(index: int, cell: tuple[str, str, str, list[str]], prefix: str) -> dict:
    app, target, cell_id, options = cell
    label = f"{prefix}-{index:02d}-{cell_id}"
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
    image = ROOT / "artifacts/hil/images" / label
    ram = image / "ram-report.json"
    return {"index": index, "label": label, "app": app, "target": target,
            "cell": cell_id, "options": options, "exit_code": result.returncode,
            "stdout": result.stdout.strip(), "stderr": result.stderr.strip(),
            "build_log": None,
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
                           "cell": cell_id, "options": options}
                          for i, (app, target, cell_id, options) in enumerate(planned)], indent=2))
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(build, i, cell, args.label_prefix): i
                   for i, cell in enumerate(planned)}
        for future in as_completed(futures):
            row = future.result()
            results.append(row)
            print(f"[{len(results)}/{len(planned)}] {row['label']} exit={row['exit_code']}", flush=True)
            args.out.write_text(json.dumps({"timestamp_utc": datetime.datetime.now(
                datetime.timezone.utc).isoformat(), "expected": len(planned),
                "completed": len(results), "passed": sum(r["exit_code"] == 0 for r in results),
                "results": sorted(results, key=lambda r: r["index"])}, indent=2) + "\n")
    return 0 if all(row["exit_code"] == 0 for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
