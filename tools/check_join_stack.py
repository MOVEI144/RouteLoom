#!/usr/bin/env python3
"""Stack gate for the P3-4 join translation units (design P3-4 §9).

Compiles each unit with `-O2 -fstack-usage` and requires every stack frame
to stay within 512 bytes with no unbounded dynamic allocation. GCC-only;
the CMake caller adds this test for GNU compilers only.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

LIMIT = 512
UNITS = (
    "components/routeloom/src/sdkv1_join_handshake.cpp",
    "components/routeloom/src/sdkv1_join_candidates.cpp",
)


def check(cxx: str, root: Path) -> int:
    failures = 0
    for unit in UNITS:
        src = root / unit
        with tempfile.TemporaryDirectory(prefix="join_stack_") as tmp:
            obj = Path(tmp) / "tu.o"
            cmd = [
                cxx, "-O2", "-fstack-usage", "-std=c++17",
                "-I", str(root / "components/routeloom/include"),
                "-c", str(src), "-o", str(obj),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"{unit}: compile failed:\n{proc.stderr}")
                return 1
            # -fstack-usage writes <output-basename>.su next to the object.
            su = obj.with_suffix(".su")
            for line in su.read_text(encoding="utf-8").splitlines():
                fields = line.split("\t")
                if len(fields) != 3:
                    print(f"{unit}: unparsable .su line: {line!r}")
                    return 1
                size = int(fields[1])
                quals = fields[2].split(",")
                if size > LIMIT or ("dynamic" in quals and "bounded" not in quals):
                    print(f"{unit}: OVER BUDGET: {fields[0]} uses {size} B ({fields[2]})")
                    failures += 1
    if failures == 0:
        print(f"join stack gate passed: all frames in {len(UNITS)} TUs <= {LIMIT} B")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", required=True, help="C++ compiler (GCC)")
    parser.add_argument("--root", required=True, help="repository root")
    args = parser.parse_args()
    return check(args.cxx, Path(args.root))


if __name__ == "__main__":
    sys.exit(main())
