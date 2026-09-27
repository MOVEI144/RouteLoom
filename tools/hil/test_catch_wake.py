"""The short-wake ROM path must refuse writes on identity/security mismatch."""

import io
import types
import unittest
from unittest.mock import patch

import catch_wake


class FakeSerial:
    def __init__(self, **_kwargs):
        self.port = None
        self.dtr = False
        self.rts = False

    def open(self):
        pass

    def close(self):
        pass


class FakeEsp:
    CHIP_NAME = "ESP32-C3"

    def __init__(self, mac, secure_boot=False, flash_encryption=False):
        self.mac = mac
        self.secure_boot = secure_boot
        self.flash_encryption = flash_encryption

    def read_mac(self, _kind):
        return self.mac

    def get_security_info(self):
        return {"parsed_flags": {"SECURE_BOOT_EN": self.secure_boot}}

    def get_secure_boot_enabled(self):
        return self.secure_boot

    def get_flash_encryption_enabled(self):
        return self.flash_encryption


class CatchWakeTest(unittest.TestCase):
    def test_mismatched_mac_never_builds_flash_command(self):
        args = types.SimpleNamespace(chip="esp32c3", mac="94:a9:90:7a:26:ac")
        esp = FakeEsp((0x94, 0xA9, 0x90, 0x7A, 0x26, 0xAD))
        with patch.object(catch_wake.serial, "Serial", FakeSerial), \
             patch.object(catch_wake, "esptool", types.SimpleNamespace(
                 detect_chip=lambda **_kwargs: esp)), \
             patch.object(catch_wake, "build_write_flash_cmd") as flash_command:
            result = catch_wake.direct_rom_recover(args, "/dev/ttyACM4", "/tmp",
                                                   1, io.StringIO())
        self.assertEqual(result, 2)
        flash_command.assert_not_called()

    def test_secure_boot_never_builds_flash_command(self):
        args = types.SimpleNamespace(chip="esp32c3", mac="94:a9:90:7a:26:ac")
        esp = FakeEsp((0x94, 0xA9, 0x90, 0x7A, 0x26, 0xAC), secure_boot=True)
        with patch.object(catch_wake.serial, "Serial", FakeSerial), \
             patch.object(catch_wake, "esptool", types.SimpleNamespace(
                 detect_chip=lambda **_kwargs: esp)), \
             patch.object(catch_wake, "build_write_flash_cmd") as flash_command:
            result = catch_wake.direct_rom_recover(args, "/dev/ttyACM4", "/tmp",
                                                   1, io.StringIO())
        self.assertEqual(result, 2)
        flash_command.assert_not_called()

    def test_flash_encryption_never_builds_flash_command(self):
        args = types.SimpleNamespace(chip="esp32c3", mac="94:a9:90:7a:26:ac")
        esp = FakeEsp((0x94, 0xA9, 0x90, 0x7A, 0x26, 0xAC), flash_encryption=True)
        with patch.object(catch_wake.serial, "Serial", FakeSerial), \
             patch.object(catch_wake, "esptool", types.SimpleNamespace(
                 detect_chip=lambda **_kwargs: esp)), \
             patch.object(catch_wake, "build_write_flash_cmd") as flash_command:
            result = catch_wake.direct_rom_recover(args, "/dev/ttyACM3", "/tmp",
                                                   1, io.StringIO())
        self.assertEqual(result, 2)
        flash_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
