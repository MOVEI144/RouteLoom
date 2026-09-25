#!/usr/bin/env python3
"""Back up and erase only the rlsec partition of a chip/MAC-verified board.

Use when testing a fresh Site state on the same physical C3/C5 reference or
bridge. The backup contains private device identity material: keep it outside
the repository in a mode-0700 directory.
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import flash  # noqa: E402
import rig  # noqa: E402

RLSEC_OFFSET = "0x190000"
RLSEC_SIZES = {"reference_node": "0x10000", "bridge_node": "0x20000"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rig", required=True)
    p.add_argument("--bench", required=True)
    p.add_argument("--board", required=True)
    p.add_argument("--backup", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--esptool", default=flash.DEFAULT_ESPTOOL)
    args = p.parse_args()
    board = rig.load_rigs(args.rig)[args.bench].boards[args.board]
    if board.chip not in ("esp32c3", "esp32c5") or not board.mac:
        raise RuntimeError("rlsec erase requires a pinned C3/C5 MAC")
    if board.app not in RLSEC_SIZES:
        raise RuntimeError("no audited rlsec layout for this app")
    rlsec_size = RLSEC_SIZES[board.app]
    repo = pathlib.Path(__file__).resolve().parents[2]
    table = (repo / f"firmware/{board.app}/partitions.csv").read_text()
    if f"rlsec,    data, nvs,     {RLSEC_OFFSET}, {rlsec_size}" not in table:
        raise RuntimeError("rlsec partition map changed; refusing erase")
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    port, _, state = rig.resolve_board_port(board)
    if state != "ONLINE" or port is None:
        raise RuntimeError(f"board port unavailable: {state}")
    identity = flash.preflight_board(board, port, args.esptool, str(out))
    backup = pathlib.Path(args.backup)
    if backup.exists() or not backup.parent.is_dir():
        raise RuntimeError("backup must be a new path in an existing private directory")
    if backup.parent.stat().st_mode & 0o077:
        raise RuntimeError("backup directory must be mode 0700")
    read = [args.esptool, "--chip", board.chip, "--port", port,
            "read-flash", RLSEC_OFFSET, rlsec_size, str(backup)]
    with (out / "read.log").open("w") as log:
        result = subprocess.run(read, stdout=log, stderr=subprocess.STDOUT,
                                timeout=120)
    if result.returncode or not backup.is_file() or backup.stat().st_size != int(rlsec_size, 16):
        raise RuntimeError("rlsec backup failed; no erase attempted")
    backup.chmod(0o600)
    digest = hashlib.sha256(backup.read_bytes()).hexdigest()
    # Recheck after read-flash reset/re-enumeration, immediately before erase.
    port, _, state = rig.resolve_board_port(board)
    if state != "ONLINE" or port is None:
        raise RuntimeError(f"board port unavailable before erase: {state}")
    identity = flash.preflight_board(board, port, args.esptool, str(out))
    erase = [args.esptool, "--chip", board.chip, "--port", port,
             "erase-region", RLSEC_OFFSET, rlsec_size]
    with (out / "erase.log").open("w") as log:
        result = subprocess.run(erase, stdout=log, stderr=subprocess.STDOUT,
                                timeout=120)
    if result.returncode:
        raise RuntimeError("rlsec erase failed; inspect erase.log")
    manifest = {"board": board.name, "chip": identity["chip"],
                "mac": identity["mac"], "offset": RLSEC_OFFSET, "size": rlsec_size,
                "backup_sha256": digest, "backup_path": str(backup), "erased": True}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
