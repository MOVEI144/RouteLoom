#!/usr/bin/env python3
"""Static RAM report and headroom guard for one firmware image.

docs/design/sdk-v1/ram-budget.md. Reads the memory summary that ESP-IDF
writes with

    idf.py size --format json2 --output-file build/size.json

(esp-idf-size 2.x, which ESP-IDF v6.0 pins: a "layout" list of memory types,
each with name/total/used/free and per-section "parts"). The raw memory map
(`--format raw`, a "memory_types" object) is accepted too, and a missing
"free" is derived as total - used, so a minor format drift degrades to the
same numbers instead of a false pass. A report with no RAM type holding
.bss is an error — the guard never passes by not finding its input.

The guarded figure is the free space of the main internal-RAM memory type that
holds static data (.bss/.data). On the ESP32-C3 that is "DRAM"; on the S3
"DIRAM"; on the C5 "HP SRAM". IRAM code shares these regions on all three
targets, so `free` is exactly the room left before dram0_0_seg overflows at
link time. Every internal RAM type is reported; flash and external RAM are
not RAM budget and are skipped.

The threshold table below is the documented floor (ram-budget.md §5);
tests/test_firmware_ram_report.py keeps the two in sync.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Minimum static-RAM headroom (bytes) per (target, app); "*" matches any app.
# 8 KiB is one feature increment of static state (group delivery added about
# 5 KB) plus margin: a change that would eat the last 8 KiB has to
# come with its own reclaim or a reviewed table change, instead of the next
# feature failing at link time.
MIN_FREE_BYTES: Dict[tuple, int] = {
    ("esp32c3", "bridge_node"): 8 * 1024,
    ("esp32c3", "reference_node"): 8 * 1024,
    ("esp32s3", "*"): 8 * 1024,
    ("esp32c5", "*"): 8 * 1024,
}
DEFAULT_MIN_FREE_BYTES = 8 * 1024

# Section names that mark the memory type holding static data (abbreviated
# names as esp-idf-size prints them by default, and the full output-section
# names seen with --no-abbrev or in the raw format).
STATIC_SECTIONS = (".bss", ".data", ".dram0.bss", ".dram0.data")
# Memory types that are not internal RAM budget.
NON_RAM_PREFIXES = ("flash", "external")
# Low-power memories (RTC SLOW/FAST, LP SRAM): reported, never guarded.
LOW_POWER_PREFIXES = ("rtc", "lp ")


class ReportError(ValueError):
    """The size report is missing or not in a recognised layout."""


def _num(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{what} is not a number: {value!r}")
    return int(value)


def memory_types(report: Any) -> List[Dict[str, Any]]:
    """Normalises either layout into [{name, total, used, free, parts}]."""
    if not isinstance(report, dict):
        raise ReportError("size report is not a JSON object")
    types: List[Dict[str, Any]] = []
    if isinstance(report.get("layout"), list):
        for entry in report["layout"]:
            if not isinstance(entry, dict) or "name" not in entry:
                raise ReportError(f"layout entry without a name: {entry!r}")
            total = _num(entry.get("total", entry.get("size", 0)), f"{entry['name']}.total")
            used = _num(entry.get("used", 0), f"{entry['name']}.used")
            parts_raw = entry.get("parts", entry.get("sections", {})) or {}
            types.append({"name": str(entry["name"]), "total": total, "used": used,
                          "free": _num(entry["free"], f"{entry['name']}.free")
                          if "free" in entry else total - used,
                          "parts": parts_raw})
    elif isinstance(report.get("memory_types"), dict):
        for name, entry in report["memory_types"].items():
            if not isinstance(entry, dict):
                raise ReportError(f"memory type {name!r} is not an object")
            total = _num(entry.get("size", entry.get("total", 0)), f"{name}.size")
            used = _num(entry.get("used", 0), f"{name}.used")
            parts_raw = entry.get("sections", entry.get("parts", {})) or {}
            types.append({"name": str(name), "total": total, "used": used,
                          "free": total - used, "parts": parts_raw})
    else:
        raise ReportError("unrecognised size report: neither 'layout' nor 'memory_types'")
    for entry in types:
        parts: Dict[str, int] = {}
        for part_name, part in entry["parts"].items():
            size = part.get("size") if isinstance(part, dict) else part
            label = part.get("abbrev_name", part_name) if isinstance(part, dict) else part_name
            parts[str(label)] = parts.get(str(label), 0) + _num(size, f"{entry['name']}.{part_name}")
        entry["parts"] = parts
    return types


def ram_types(types: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [t for t in types
            if t["total"] > 0 and not t["name"].lower().startswith(NON_RAM_PREFIXES)]


def static_type(types: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The main internal RAM type holding .bss/.data.

    esp-idf-size abbreviates a section to its last dotted component, so the
    RTC/LP memories' .rtc.data/.rtc.bss (RTC_DATA_ATTR, deep-sleep builds)
    also show up as ".data"/".bss". Those low-power memories are reported
    but never guarded; among the rest the largest type is the main SRAM
    that dram0_0_seg lives in.
    """
    holders = [t for t in ram_types(types)
               if not t["name"].lower().startswith(LOW_POWER_PREFIXES)
               and any(part in STATIC_SECTIONS and size > 0 for part, size in t["parts"].items())]
    if not holders:
        raise ReportError("no internal RAM memory type holds .bss/.data in the size report")
    return max(holders, key=lambda t: t["total"])


def threshold(target: str, app: str) -> int:
    return MIN_FREE_BYTES.get((target, app),
                              MIN_FREE_BYTES.get((target, "*"), DEFAULT_MIN_FREE_BYTES))


def evaluate(report: Any, target: str, app: str, cell: str = "") -> Dict[str, Any]:
    types = memory_types(report)
    guarded = static_type(types)
    floor = threshold(target, app)
    return {
        "cell": cell or f"{app}-{target}",
        "target": target,
        "app": app,
        "memory": [{k: t[k] for k in ("name", "total", "used", "free", "parts")}
                   for t in ram_types(types)],
        "guard": {
            "memory_type": guarded["name"],
            "static_bss": guarded["parts"].get(".bss", 0) + guarded["parts"].get(".dram0.bss", 0),
            "static_data": guarded["parts"].get(".data", 0) + guarded["parts"].get(".dram0.data", 0),
            "free": guarded["free"],
            "min_free": floor,
            "passed": guarded["free"] >= floor,
        },
    }


def markdown(result: Dict[str, Any]) -> str:
    guard = result["guard"]
    verdict = "PASS" if guard["passed"] else "FAIL"
    lines = [
        f"### Static RAM: {result['cell']}",
        "",
        "| Memory type | Used | Total | Free | Used % | Largest parts |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for mem in result["memory"]:
        pct = 100.0 * mem["used"] / mem["total"] if mem["total"] else 0.0
        parts = ", ".join(f"{name} {size}" for name, size in
                          sorted(mem["parts"].items(), key=lambda p: -p[1])[:4])
        lines.append(f"| {mem['name']} | {mem['used']} | {mem['total']} | "
                     f"{mem['free']} | {pct:.1f} | {parts} |")
    lines += [
        "",
        f"Guard ({guard['memory_type']}, .bss {guard['static_bss']} B, "
        f".data {guard['static_data']} B): free {guard['free']} B vs floor "
        f"{guard['min_free']} B — **{verdict}**",
        "",
    ]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("size_json", type=Path,
                        help="output of idf.py size --format json2 --output-file")
    parser.add_argument("--target", required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--cell", default="")
    parser.add_argument("--json-out", type=Path, help="write the machine-readable report here")
    parser.add_argument("--summary", type=Path,
                        help="append the Markdown report here (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.size_json.read_text(encoding="utf-8"))
        result = evaluate(report, args.target, args.app, args.cell)
    except (OSError, ValueError) as error:  # ReportError and JSON errors
        message = f"firmware_ram_report: {args.size_json}: {error}"
        print(message, file=sys.stderr)
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as out:
                out.write(f"### Static RAM: {args.cell or args.app}\n\n**ERROR** {error}\n\n")
        return 2
    text = markdown(result)
    print(text)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as out:
            out.write(text + "\n")
    if args.json_out:
        args.json_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if not result["guard"]["passed"]:
        guard = result["guard"]
        print(f"firmware_ram_report: {result['cell']}: static RAM headroom "
              f"{guard['free']} B is below the {guard['min_free']} B floor "
              f"(docs/design/sdk-v1/ram-budget.md)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
