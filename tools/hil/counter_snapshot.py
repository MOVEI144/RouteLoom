#!/usr/bin/env python3
"""Read a pinned board's security NVS and export only counter metadata.

The raw rlsec image stays in a mode-0700 private directory outside the repo.
The report contains verified counter identities and high-water values, never
the NVS contents, device keys or replay records.
"""

import argparse
import base64
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import zlib

import flash
import reprovision_reset
import rig


def summarize(entries: list[dict]) -> dict:
    counters = []
    invalid = []
    for entry in entries:
        if entry.get("namespace") != "rlcounter" or entry.get("key") == "cmax":
            continue
        key = str(entry.get("key", ""))
        if not key.startswith("c") or entry.get("encoding") != "blob_data":
            invalid.append(key)
            continue
        try:
            raw = base64.b64decode(entry["data"], validate=True)
            if len(raw) != 32:
                raise ValueError("wrong counter record size")
            context, epoch, direction, layout, reserved, highwater, generation, crc = (
                struct.unpack("<IIBB6sQII", raw))
            if layout != 2 or crc != zlib.crc32(raw[:28]):
                raise ValueError("counter record layout or CRC invalid")
        except (KeyError, ValueError, struct.error) as exc:
            invalid.append(f"{key}: {exc}")
            continue
        counters.append({"slot": key, "context_id": f"{context:08x}",
                         "key_epoch": epoch, "direction": direction,
                         "high_water_exclusive": highwater,
                         "generation": generation})
    counters.sort(key=lambda row: row["slot"])
    witness = next((x.get("data") for x in entries if x.get("namespace") == "rlcounter"
                    and x.get("key") == "cmax"), None)
    return {"counter_records": counters, "counter_witness": witness,
            "invalid_records": invalid}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rig", required=True)
    parser.add_argument("--bench", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    board = rig.load_rigs(args.rig)[args.bench].boards[args.board]
    if board.chip not in ("esp32c3", "esp32c5", "esp32c6") or not board.mac:
        parser.error("board requires a pinned C3/C5/C6 chip and MAC")
    if board.app not in reprovision_reset.RLSEC_SIZES:
        parser.error("unknown audited security NVS layout")
    private_dir = pathlib.Path(args.private_dir).resolve()
    repo = pathlib.Path(__file__).resolve().parents[2]
    if (not private_dir.is_dir() or private_dir.stat().st_mode & 0o077 or
            private_dir == repo or repo in private_dir.parents):
        parser.error("private-dir must exist outside the repo with mode 0700")
    if not args.label.isascii() or not args.label.replace("-", "").replace("_", "").isalnum():
        parser.error("label must be ASCII letters/digits/dashes/underscores")
    raw_path = private_dir / f"rlsec-{args.board}-{args.label}.bin"
    if raw_path.exists():
        parser.error(f"private backup already exists: {raw_path}")
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    port, _, state = rig.resolve_board_port(board)
    if state != "ONLINE" or port is None:
        raise RuntimeError(f"board is {state}")
    preflight_dir = private_dir / f"preflight-{args.board}-{args.label}"
    preflight_dir.mkdir(mode=0o700)
    flash.preflight_board(board, port, flash.DEFAULT_ESPTOOL,
                          str(preflight_dir))
    flash.verify_device_partition_table(flash.DEFAULT_ESPTOOL, board.chip, port,
                                        board.build_dir(str(repo)))
    identity = flash.preflight_board(board, port, flash.DEFAULT_ESPTOOL,
                                     str(preflight_dir))
    cmd = [flash.DEFAULT_ESPTOOL, "--chip", board.chip, "--port", port,
           "read-flash", reprovision_reset.RLSEC_OFFSET,
           reprovision_reset.RLSEC_SIZES[board.app], str(raw_path)]
    read = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    (preflight_dir / "read.log").write_text(read.stdout + read.stderr)
    if read.returncode or not raw_path.is_file() or raw_path.stat().st_size != int(
            reprovision_reset.RLSEC_SIZES[board.app], 16):
        raise RuntimeError("rlsec read failed; see private read.log")
    raw_path.chmod(0o600)
    parsed = subprocess.run([
        "docker", "run", "--rm", "--entrypoint", "python3", "-v",
        f"{private_dir}:/data:ro", "espressif/idf:v6.0.3",
        "/opt/esp/idf/components/nvs_flash/nvs_partition_tool/nvs_tool.py",
        "-d", "minimal", "-f", "json", f"/data/{raw_path.name}"],
        capture_output=True, text=True, timeout=60)
    if parsed.returncode:
        (preflight_dir / "parse-error.log").write_text(parsed.stderr)
        raise RuntimeError("NVS parse failed; see private parse-error.log")
    summary = summarize(json.loads(parsed.stdout))
    summary.update({"board": board.name, "chip": identity["chip"],
                    "mac": identity["mac"], "label": args.label,
                    "raw_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                    "raw_size": raw_path.stat().st_size})
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 0 if not summary["invalid_records"] else 1


if __name__ == "__main__":
    sys.exit(main())
