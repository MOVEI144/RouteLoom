"""protocol/abi-golden must match the core C ABI layout (ILP32 and LP64)."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AbiGoldenTest(unittest.TestCase):
    def test_layout_matches_golden(self) -> None:
        run = subprocess.run([sys.executable, str(ROOT / "tools/abi_golden.py")],
                             capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
