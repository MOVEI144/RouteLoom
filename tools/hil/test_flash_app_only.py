"""The maintenance app-only path must never rewrite partition metadata."""
import json
import os
import tempfile
import unittest

from tools.hil.flash import build_write_flash_cmd, FlashError


class FlashAppOnlyTests(unittest.TestCase):
    def test_missing_app_offset_refuses_fallback(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({'app': {'file': 'reference_node.bin'}}, f)
            with self.assertRaises(FlashError):
                build_write_flash_cmd(build, '/dev/null', 'esptool', None, 115200, True)

    def test_app_only_needs_no_fallback_boot_bins(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({'app': {'offset': '0x20000', 'file': 'app/image.bin'}}, f)
            os.makedirs(os.path.join(build, 'app'))
            open(os.path.join(build, 'app/image.bin'), 'wb').close()
            _, files, fallback = build_write_flash_cmd(build, '/dev/null', 'esptool',
                                                       None, 115200, True)
            self.assertTrue(fallback)
            self.assertEqual(set(files), {'0x20000'})

    def test_fallback_app_only(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({'app': {'offset': '0x10000', 'file': 'reference_node.bin'}}, f)
            for name in ('reference_node.bin', 'bootloader/bootloader.bin',
                         'partition_table/partition-table.bin'):
                path = os.path.join(build, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, 'wb').close()
            _, files, fallback = build_write_flash_cmd(build, '/dev/null', 'esptool',
                                                       None, 115200, True)
            self.assertTrue(fallback)
            self.assertEqual(set(files), {'0x10000'})


if __name__ == '__main__':
    unittest.main()
