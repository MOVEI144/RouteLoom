"""The maintenance app-only path must never rewrite partition metadata."""
import json
import os
import tempfile
import unittest

from tools.hil.flash import build_write_flash_cmd, FlashError


def _touch(build, name):
    path = os.path.join(build, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'wb').close()


class FlashAppOnlyTests(unittest.TestCase):
    def test_missing_otadata_refuses_app_only(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({'app': {'offset': '0x40000', 'file': 'reference_node.bin'}}, f)
            with self.assertRaises(FlashError):
                build_write_flash_cmd(build, '/dev/null', 'esptool', None, 115200, True)

    def test_app_only_writes_ota_0_and_otadata(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({'app': {'offset': '0x40000', 'file': 'reference_node.bin'},
                           'otadata': {'offset': '0x10000', 'file': 'ota_data_initial.bin'}},
                          f)
            for name in ('reference_node.bin', 'ota_data_initial.bin',
                         'bootloader/bootloader.bin', 'partition_table/partition-table.bin'):
                _touch(build, name)
            _, files, fallback = build_write_flash_cmd(build, '/dev/null', 'esptool',
                                                       None, 115200, True)
            self.assertTrue(fallback)
            self.assertEqual(set(files), {'0x10000', '0x40000'})

    def test_full_fallback_uses_pt_4m_v2(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({}, f)
            for name in ('reference_node.bin', 'ota_data_initial.bin',
                         'bootloader/bootloader.bin', 'partition_table/partition-table.bin'):
                _touch(build, name)
            _, files, fallback = build_write_flash_cmd(build, '/dev/null', 'esptool',
                                                       None, 115200, False)
            self.assertTrue(fallback)
            self.assertEqual(files['0x40000'], os.path.join(build, 'reference_node.bin'))
            self.assertEqual(set(files), {'0x0', '0x8000', '0x10000', '0x40000'})


if __name__ == '__main__':
    unittest.main()
