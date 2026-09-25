#!/usr/bin/env python3
"""Restore a private rlsec backup to the exact chip/MAC it came from."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import flash  # noqa: E402
import rig  # noqa: E402
from reprovision_reset import RLSEC_OFFSET, RLSEC_SIZES  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rig", required=True)
    p.add_argument("--bench", required=True)
    p.add_argument("--board", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--esptool", default=flash.DEFAULT_ESPTOOL)
    args = p.parse_args()

    board = rig.load_rigs(args.rig)[args.bench].boards[args.board]
    if board.chip not in ("esp32c3", "esp32c5") or not board.mac or board.app not in RLSEC_SIZES:
        p.error("restore requires an audited C3/C5 board with pinned MAC")
    expected_size = RLSEC_SIZES[board.app]
    table = (pathlib.Path(__file__).resolve().parents[2] /
             f"firmware/{board.app}/partitions.csv").read_text()
    if f"rlsec,    data, nvs,     {RLSEC_OFFSET}, {expected_size}" not in table:
        p.error("rlsec partition map changed")
    manifest = json.loads(pathlib.Path(args.manifest).read_text())
    if (manifest.get("board") != board.name or
            manifest.get("chip") != board.chip or
            manifest.get("mac") != board.mac or
            manifest.get("offset") != RLSEC_OFFSET or
            manifest.get("size") != expected_size or
            manifest.get("erased") is not True):
        p.error("backup manifest does not match the pinned board and partition")
    backup = pathlib.Path(manifest["backup_path"])
    if (not backup.is_file() or backup.parent.stat().st_mode & 0o077 or
            backup.stat().st_size != int(expected_size, 16) or
            hashlib.sha256(backup.read_bytes()).hexdigest() != manifest["backup_sha256"]):
        p.error("private backup is missing, exposed, truncated or changed")

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    port, _, state = rig.resolve_board_port(board)
    if state != "ONLINE" or port is None:
        p.error(f"target port unavailable: {state}")
    identity = flash.preflight_board(board, port, args.esptool, str(out))
    cmd = [args.esptool, "--chip", board.chip, "--port", port,
           "write-flash", RLSEC_OFFSET, str(backup)]
    with (out / "write.log").open("w") as log:
        result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode:
        raise RuntimeError("rlsec write failed; inspect write.log")
    port, _, state = rig.resolve_board_port(board)
    if state != "ONLINE" or port is None:
        raise RuntimeError(f"target port unavailable for verification: {state}")
    flash.preflight_board(board, port, args.esptool, str(out))
    readback = backup.parent / f"{board.name}-rlsec-readback.bin"
    if readback.exists():
        raise RuntimeError("private readback path already exists")
    try:
        cmd = [args.esptool, "--chip", board.chip, "--port", port,
               "read-flash", RLSEC_OFFSET, expected_size, str(readback)]
        with (out / "verify.log").open("w") as log:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        if result.returncode or not readback.is_file() or readback.read_bytes() != backup.read_bytes():
            raise RuntimeError("rlsec readback did not match backup")
    finally:
        readback.unlink(missing_ok=True)
    summary = {"board": board.name, "chip": identity["chip"], "mac": identity["mac"],
               "offset": RLSEC_OFFSET, "size": expected_size,
               "sha256": manifest["backup_sha256"], "verified": True}
    (out / "manifest.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
