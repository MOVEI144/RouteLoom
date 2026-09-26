#!/usr/bin/env python3
"""Safety regression: flash preflight rejects a swapped or unsupported board."""

import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import flash
import provision_console
import rig


class BootLogTest(unittest.TestCase):
    def test_boot_log_failures_flag_heap_floor_and_wifi_init(self):
        text = ("[t] I (754) RouteLoom: ESP-NOW ready heap: free=22940 largest=20480 min=22888 bytes\n"
                "[t] E (760) RouteLoom: BOOT_HEAP_BELOW_FLOOR free=5956 largest=3968 floor=8192 bytes\n"
                "[t] E (400) RouteLoomBridge: esp_wifi_init failed: ESP_ERR_NO_MEM\n"
                "[t] E (410) phy_init: failed to allocate memory for RF calibration data\n")
        failures = flash.boot_log_failures(text)
        self.assertEqual(len(failures), 3)
        self.assertIn("BOOT_HEAP_BELOW_FLOOR", failures[0])
        self.assertEqual(flash.boot_log_failures("I (754) RouteLoom: ESP-NOW ready heap: free=22940\n"), [])


class PreflightTest(unittest.TestCase):
    def test_security_enabled_refuses_before_write(self):
        board = rig.Board(name="ref", app="reference_node", chip="esp32c3",
                          mac="94:a9:90:7a:b5:60")
        identity = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Chip type: ESP32-C3 (rev)\nMAC: 94:a9:90:7a:b5:60\n", stderr="")
        with tempfile.TemporaryDirectory() as out:
            for security in ("Secure Boot: Enabled\nFlash Encryption: Disabled\n",
                             "Secure Boot: Disabled\nFlash Encryption: Enabled\n",
                             "Secure Boot: Disabled\n"):
                report = subprocess.CompletedProcess(args=[], returncode=0,
                                                     stdout=identity.stdout + security,
                                                     stderr="")
                with patch.object(flash.subprocess, "run", side_effect=[identity, report]):
                    with self.assertRaises(flash.FlashError):
                        flash.preflight_board(board, "/dev/fake", "esptool", out)

    def test_unpinned_mac_refuses(self):
        board = rig.Board(name="ref", app="reference_node", chip="esp32c3")
        with tempfile.TemporaryDirectory() as out:
            with patch.object(flash.subprocess, "run") as run:
                with self.assertRaises(flash.FlashError):
                    flash.preflight_board(board, "/dev/fake", "esptool", out)
                run.assert_not_called()

    def test_security_probe_rejects_swapped_board(self):
        board = rig.Board(name="ref", chip="esp32c3", mac="94:a9:90:7a:b5:60")
        identity = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Chip type: ESP32-C3 (rev)\nMAC: 94:a9:90:7a:b5:60\n", stderr="")
        security = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Chip type: ESP32-C3 (rev)\nMAC: 94:a9:90:6a:ee:c4\n"
                   "Secure Boot: Disabled\nFlash Encryption: Disabled\n", stderr="")
        with tempfile.TemporaryDirectory() as out:
            with patch.object(flash.subprocess, "run", side_effect=[identity, security]):
                with self.assertRaises(flash.FlashError):
                    flash.preflight_board(board, "/dev/fake", "esptool", out)

    def test_provision_console_uses_security_preflight_before_serial_write(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = ["provision_console.py", "--port", "/dev/fake", "--mac",
                    "94:a9:90:7a:b5:60", "--chip", "esp32c3", "--ctl", "ctl",
                    "--ca-key", "/tmp/ca", "--spec", "/tmp/spec", "--node",
                    "0000000000000002", "--serial", "1", "--challenge", "a" * 64,
                    "--out-dir", str(pathlib.Path(directory) / "new")]
            with patch.object(sys, "argv", argv), \
                 patch.object(provision_console.flash, "preflight_board",
                              side_effect=flash.FlashError("security enabled")) as preflight, \
                 patch.object(provision_console.serial, "Serial") as serial_port:
                with self.assertRaises(flash.FlashError):
                    provision_console.main()
                preflight.assert_called_once()
                serial_port.assert_not_called()

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
                security = subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout=f"Chip type: ESP32-{chip} (rev)\nMAC: {mac}\n"
                           "Secure Boot: Disabled\nFlash Encryption: Disabled\n", stderr="")
                with patch.object(flash.subprocess, "run", side_effect=[result, security]):
                    if passes:
                        self.assertEqual(flash.preflight_board(board, "/dev/fake", "esptool", out)["mac"], mac)
                    else:
                        with self.assertRaises(flash.FlashError):
                            flash.preflight_board(board, "/dev/fake", "esptool", out)

    def test_c6_requires_full_eui64_match(self):
        board = rig.Board(name="ref-c", app="reference_node", chip="esp32c6",
                          mac="10:bd:a3:ff:fe:b1:47:54")
        with tempfile.TemporaryDirectory() as out:
            for mac, passes in ((board.mac, True),
                                ("10:bd:a3:ff:fe:b1:48:a8", False),
                                ("10:bd:a3:b1:47:54", False)):
                result = subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout=f"Chip type:          ESP32-C6FH4 (rev)\nMAC:                {mac}\n",
                    stderr="")
                security = subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout=f"Chip type: ESP32-C6FH4 (rev)\nMAC: {mac}\n"
                           "Secure Boot: Disabled\nFlash Encryption: Disabled\n", stderr="")
                with patch.object(flash.subprocess, "run", side_effect=[result, security]):
                    if passes:
                        self.assertEqual(flash.preflight_board(board, "/dev/fake", "esptool", out)["mac"], mac)
                    else:
                        with self.assertRaises(flash.FlashError):
                            flash.preflight_board(board, "/dev/fake", "esptool", out)


if __name__ == "__main__":
    unittest.main()
