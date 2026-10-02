#!/usr/bin/env python3
"""Generate RX allow-list overlays and manual bench steps; never access hardware."""

from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
from pathlib import Path


def neighbors(topology: str, count: int) -> list[list[int]]:
    if topology == "line7" and count == 7:
        edges = [(i, i + 1) for i in range(6)]
    elif topology == "diamond" and count == 4:
        edges = [(0, 1), (0, 2), (1, 3), (2, 3)]
    elif topology == "star" and 2 <= count <= 9:
        edges = [(0, i) for i in range(1, count)]
    else:
        raise ValueError("line7 needs 7 rows, diamond 4, star 2–9 (first row is center)")
    adjacent: list[list[int]] = [[] for _ in range(count)]
    for left, right in edges:
        adjacent[left].append(right)
        adjacent[right].append(left)
    return adjacent


def read_boards(table: Path) -> list[dict[str, str]]:
    with table.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not {"name", "by_id", "mac", "chip", "app"} <= set(reader.fieldnames or []):
            raise ValueError("CSV needs name,by_id,mac,chip,app; optional probe_mac")
        boards = list(reader)
    for board in boards:
        if any(not isinstance(board.get(key), str) for key in ("name", "by_id", "mac", "chip", "app")):
            raise ValueError("incomplete CSV row")
        name = board["name"]
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            raise ValueError("board name must contain only letters, digits, _ or -")
        port = board["by_id"]
        if (Path(port).parent != Path("/dev/serial/by-id") or
                any(c in port for c in "*?[]\n\r") or Path(port).name in ("", ".", "..")):
            raise ValueError(f"{name}: by_id must be a literal /dev/serial/by-id/ path")
        if board["chip"] not in ("esp32c3", "esp32c6", "esp32s3"):
            raise ValueError(f"{name}: chip must be esp32c3, esp32c6 or esp32s3")
        if board["app"] not in ("bridge_node", "reference_node", "bench_node"):
            raise ValueError(f"{name}: unsupported firmware app")
        if not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", board["mac"]):
            raise ValueError(f"{name}: mac must be the six-byte Wi-Fi STA MAC")
        board["mac"] = board["mac"].lower()
        probe = board.get("probe_mac") or board["mac"]
        octets = 8 if board["chip"] == "esp32c6" else 6
        if not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){" + str(octets - 1) + "}", probe):
            raise ValueError(f"{name}: probe_mac must match esptool chip-id ({octets} bytes)")
        board["probe_mac"] = probe.lower()
    for column in ("name", "by_id", "mac", "probe_mac"):
        if len({b[column] for b in boards}) != len(boards):
            raise ValueError(f"duplicate {column}")
    return boards


def generate(topology: str, table: Path, output: Path) -> None:
    boards = read_boards(table)
    adjacent = neighbors(topology, len(boards))
    output.mkdir(parents=True, exist_ok=False)
    rig_boards = {}
    steps = [f"# {topology} HIL topology", "",
             "Rows define the line order, diamond G/R1/R2/E, or star center/leaves.",
             "These filters simulate adjacency; they do not measure range or RF isolation.",
             "Run build steps from the repository root, one board at a time.",
             "Retain the site's existing role/profile overrides and provisioning.",
             "Clear any existing DROP_RX_MAC setting before using these overlays.", "",
             "## Build", "", "```sh"]
    flashes = []
    for i, board in enumerate(boards):
        name = board["name"]
        allow = ",".join(boards[j]["mac"] for j in adjacent[i])
        overlay = output / f"{name}.sdkconfig"
        overlay.write_text(f'CONFIG_ROUTELOOM_HIL_RX_ALLOW_MACS="{allow}"\n', encoding="utf-8")
        label = f"{topology}-{name}"
        steps.append(shlex.join(["tools/hil/build_image.sh", board["app"], board["chip"], label]) +
                     f' "$(cat {shlex.quote(str(overlay))})"')
        rig_boards[name] = {"app": board["app"], "chip": board["chip"],
                            "mac": board["probe_mac"], "port_globs": [board["by_id"]],
                            "console": "none" if board["app"] == "bridge_node" else "usb-serial-jtag"}
        flashes.append(shlex.join(["python3", "tools/hil/flash.py", "--rig", str(output / "rig.json"),
                                   "--bench", topology, "--board", name, "--image-dir",
                                   f"artifacts/hil/images/{label}"]))
    steps += ["```", "", "## Flash (only in an authorized hardware round)", "",
              "Reserve the boards/serial ports and follow docs/hil.md preflight first.",
              "The existing flasher verifies chip/base MAC, security state and partition layout.",
              "It requires a full flash for signed bundles, which can reset OTA state.",
              "Do not erase NVS, enable secure boot/flash encryption, or write eFuses.",
              "Do not flash as part of overlay generation; review the steps and site backups.",
              "", "```sh", *flashes, "```", ""]
    (output / "rig.json").write_text(json.dumps({"rigs": {topology: {"boards": rig_boards}}},
                                                indent=2) + "\n", encoding="utf-8")
    (output / "STEPS.md").write_text("\n".join(steps), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("topology", choices=("line7", "diamond", "star"))
    parser.add_argument("table", type=Path, help="ordered CSV board table")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    try:
        generate(args.topology, args.table, args.out)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
