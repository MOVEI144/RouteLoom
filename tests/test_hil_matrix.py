"""The HIL matrix loader plans rigs without touching hardware."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.hil import rig, scenarios


class HilMatrixTests(unittest.TestCase):
    def test_two_site_move_requires_two_gateways(self):
        bench = rig.load_rigs("tools/hil/rigs.yaml")["bench-2026-09-29-h0"]
        with patch.object(rig, "resolve_rig", side_effect=AssertionError("hardware touched")):
            plan = scenarios.matrix_plan("J05-A", bench, Path("tests/e2e/scenarios.json"))
        self.assertFalse(plan["ready"], "one gateway cannot represent two RF sites")
        self.assertIn("bridge:1", plan["missing"])

    def test_shared_row_preserves_acceptance_and_matches_distinct_boards(self):
        rigs = rig.load_rigs("tools/hil/rigs.yaml")
        bench = rigs["bench-2026-09-29-h0"]
        manifest = Path("tests/e2e/scenarios.json")
        with patch.object(rig, "resolve_rig", side_effect=AssertionError("hardware touched")):
            plan = scenarios.matrix_plan("M06", bench, manifest)
        self.assertTrue(plan["ready"])
        self.assertEqual(len(set(plan["boards"].values())), 3)
        self.assertEqual(plan["verdict"], "NOT_RUN")
        row = next(r for r in json.loads(manifest.read_text())["rows"] if r["id"] == "M06")
        self.assertEqual(plan["pass"], row["pass"])

    def test_missing_chip_manual_and_unknown_rows_are_not_passes(self):
        bench = rig.load_rigs("tools/hil/rigs.yaml")["bench-2026-09-29-h0"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "matrix.json"
            row = {"id": "X", "tier": ["hil"], "status": "pending", "pass": "20/20",
                   "hil": {"rounds": ["H4"], "run": "manual",
                           "requires": [{"role": "reference", "count": 1,
                                         "chips": ["esp32s3"]}]}}
            path.write_text(json.dumps({"rows": [row]}))
            plan = scenarios.matrix_plan("X", bench, path)
            self.assertFalse(plan["ready"])
            self.assertEqual(plan["missing"], ["reference:0"])
            self.assertEqual(plan["run"], "manual")
            with self.assertRaises(scenarios.ScenarioConfigError):
                scenarios.matrix_plan("unknown", bench, path)
