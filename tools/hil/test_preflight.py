#!/usr/bin/env python3
"""Safety regression: flash preflight rejects a swapped or unsupported board."""

import subprocess
import tempfile
import unittest
from unittest.mock import patch

import flash
import rig


class PreflightTest(unittest.TestCase):
    def test_only_expected_chip_and_mac_pass(self):
        board = rig.Board(name="ref", app="reference_node", chip="esp32c3",
                          mac="94:a9:90:7a:b5:60")
        with tempfile.TemporaryDirectory() as out:
            for chip, mac, passes in (
                ("C3", "94:a9:90:7a:b5:60", True),
                ("C3", "94:a9:90:7a:26:ac", False),
                ("C6", "94:a9:90:7a:b5:60", False),
            ):
                result = subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout=f"Chip type:          ESP32-{chip} (rev)\nMAC:                {mac}\n",
                    stderr="")
                with patch.object(flash.subprocess, "run", return_value=result):
                    if passes:
                        self.assertEqual(flash.preflight_board(board, "/dev/fake", "esptool", out)["mac"], mac)
                    else:
                        with self.assertRaises(flash.FlashError):
                            flash.preflight_board(board, "/dev/fake", "esptool", out)


if __name__ == "__main__":
    unittest.main()
