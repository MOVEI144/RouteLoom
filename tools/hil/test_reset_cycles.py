#!/usr/bin/env python3
"""Regression checks for reset-cycle evidence accounting."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import reset_cycles


class ResetCycleAccountingTest(unittest.TestCase):
    def test_recovery_measures_delivery_completion_after_reset(self):
        clock = [0.0]

        def sleep(seconds):
            clock[0] += seconds

        def probe(*args):
            clock[0] += 3.0
            return {"delivery": {"state": "delivered"}, "latency_ms": 3000.0}

        board = SimpleNamespace(role="reference", chip="esp32c6", mac="test")
        bench = SimpleNamespace(boards={"relay": board})
        with tempfile.TemporaryDirectory() as directory:
            # Console is replaced below; leave the empty log for boot diagnostics.
            Path(directory, "console.log").touch()
            argv = ["reset_cycles", "--rig", "test", "--bench", "test",
                    "--board", "relay", "--ctl", "test", "--socket", "test",
                    "--destination", "3", "--cycles", "1", "--sends", "1",
                    "--baseline", "0", "--out", directory]
            with (patch("sys.argv", argv),
                  patch.object(reset_cycles.rig, "load_rigs", return_value={"test": bench}),
                  patch.object(reset_cycles.rig, "resolve_board_port",
                               return_value=("test", None, "ONLINE")),
                  patch.object(reset_cycles.flash, "preflight_board", return_value={}),
                  patch.object(reset_cycles.serial, "Serial"),
                  patch.object(reset_cycles, "Console"),
                  patch.object(reset_cycles, "ctl", return_value={}),
                  patch.object(reset_cycles, "probe", side_effect=probe),
                  patch.object(reset_cycles.time, "sleep", side_effect=sleep),
                  patch.object(reset_cycles.time, "monotonic", side_effect=lambda: clock[0])):
                self.assertEqual(reset_cycles.main(), 0)
            result = json.loads(Path(directory, "result.json").read_text())
        cycle = result["cycle_results"][0]
        self.assertEqual(cycle["recovery_s"], 3.0)
        self.assertEqual(result["summary"]["recovery_s_max"], 3.0)

    def test_idempotency_full_after_host_admission_is_counted(self):
        sends = [
            {"response": {"accepted": True, "request": 7},
             "delivery": {"state": "failed", "reason": "IDEMPOTENCY_FULL"}},
            {"response": {"accepted": False, "error": "IDEMPOTENCY_FULL"}},
            {"response": {"accepted": True, "request": 8},
             "delivery": {"state": "delivered"}},
        ]
        self.assertEqual(reset_cycles.count_idempotency_full(sends), 2)


if __name__ == "__main__":
    unittest.main()
