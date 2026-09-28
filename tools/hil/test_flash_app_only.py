"""The maintenance app-only path must never rewrite partition metadata."""
import json
import hashlib
import os
import subprocess
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.hil import flash
from tools.hil.flash import build_write_flash_cmd, FlashError


def _touch(build, name):
    path = os.path.join(build, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'wb').close()


def _pt4m_table():
    rows = (('nvs', 1, 2, 0x9000, 0x6000),
            ('phy_init', 1, 1, 0xf000, 0x1000),
            ('otadata', 1, 0, 0x10000, 0x2000),
            ('rlcfg', 1, 2, 0x12000, 0x6000),
            ('rlkeys', 1, 2, 0x18000, 0x3000),
            ('rlsec', 1, 2, 0x20000, 0x20000),
            ('ota_0', 0, 0x10, 0x40000, 0x1d0000),
            ('ota_1', 0, 0x11, 0x210000, 0x1d0000),
            ('coredump', 1, 3, 0x3e0000, 0x10000))
    table = b''.join(struct.pack('<HBBII16sI', 0x50aa, kind, subtype,
                                 offset, size, name.encode(), 0)
                     for name, kind, subtype, offset, size in rows)
    table += b'\xeb\xeb' + b'\xff' * 14 + hashlib.md5(table).digest()
    return table + b'\xff' * (0xc00 - len(table))


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
            with open(os.path.join(build, 'ota_data_initial.bin'), 'wb') as f:
                f.write(b'\xff' * 0x2000)
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
            with open(os.path.join(build, 'ota_data_initial.bin'), 'wb') as f:
                f.write(b'\xff' * 0x2000)
            _, files, fallback = build_write_flash_cmd(build, '/dev/null', 'esptool',
                                                       None, 115200, False)
            self.assertTrue(fallback)
            self.assertEqual(files['0x40000'], os.path.join(build, 'reference_node.bin'))
            self.assertEqual(set(files), {'0x0', '0x8000', '0x10000', '0x40000'})

    def test_c5_fallback_uses_c5_bootloader_offset(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({}, f)
            for name in ('reference_node.bin', 'ota_data_initial.bin',
                         'bootloader/bootloader.bin', 'partition_table/partition-table.bin'):
                _touch(build, name)
            _, files, _ = build_write_flash_cmd(build, '/dev/null', 'esptool',
                                                'esp32c5', 115200, False)
            self.assertEqual(set(files), {'0x2000', '0x8000', '0x10000', '0x40000'})

    def test_app_only_refuses_partition_overwrite_and_nonblank_otadata(self):
        with tempfile.TemporaryDirectory() as build:
            args = {'app': {'offset': '0x20000', 'file': 'reference_node.bin'},
                    'otadata': {'offset': '0x10000', 'file': 'ota_data_initial.bin'}}
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump(args, f)
            _touch(build, 'reference_node.bin')
            with open(os.path.join(build, 'ota_data_initial.bin'), 'wb') as f:
                f.write(b'\xff' * 0x2000)
            with self.assertRaises(FlashError):
                build_write_flash_cmd(build, '/dev/null', 'esptool',
                                      'esp32c3', 115200, True)
            args['app']['offset'] = '0x40000'
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump(args, f)
            with open(os.path.join(build, 'ota_data_initial.bin'), 'wb') as f:
                f.write(b'\0' * 0x2000)
            with self.assertRaises(FlashError):
                build_write_flash_cmd(build, '/dev/null', 'esptool',
                                      'esp32c3', 115200, True)

    def test_raw_flash_checks_physical_four_mb_before_write(self):
        board = SimpleNamespace(chip='esp32c3', flash_baud=115200)
        with tempfile.TemporaryDirectory() as out, \
                patch.object(flash, 'preflight_board', return_value={}) as preflight, \
                patch.object(flash, 'build_write_flash_cmd',
                             side_effect=FlashError('stop before write')):
            with self.assertRaises(FlashError):
                flash._flash_board_from_dir(board, '/dev/fake', out, 'esptool',
                                          False, 0, 1, out)
            self.assertEqual(preflight.call_args.kwargs['minimum_flash_bytes'], 0x400000)

    def test_app_only_refuses_old_device_partition_table(self):
        with tempfile.TemporaryDirectory() as build:
            with open(os.path.join(build, 'flasher_args.json'), 'w') as f:
                json.dump({'app': {'offset': '0x40000', 'file': 'reference_node.bin'},
                           'otadata': {'offset': '0x10000', 'file': 'ota_data_initial.bin'}}, f)
            _touch(build, 'reference_node.bin')
            table = os.path.join(build, 'partition_table/partition-table.bin')
            os.makedirs(os.path.dirname(table), exist_ok=True)
            with open(table, 'wb') as f:
                f.write(_pt4m_table())
            with open(os.path.join(build, 'ota_data_initial.bin'), 'wb') as f:
                f.write(b'\xff' * 0x2000)
            board = SimpleNamespace(name='ref', app='reference_node', chip='esp32c3',
                                    flash_baud=115200, console='none')
            result = subprocess.CompletedProcess([], 1, '', 'device table differs')
            with patch.object(flash, 'preflight_board', return_value={}), \
                    patch.object(flash.subprocess, 'run', return_value=result) as run:
                with self.assertRaises(FlashError):
                    flash._flash_board_from_dir(board, '/dev/fake', build, 'esptool',
                                               True, 0, 1, build)
            self.assertIn('verify-flash', run.call_args.args[0])
            self.assertNotIn('write-flash', run.call_args.args[0])

    def test_local_old_table_cannot_authorize_app_only(self):
        with tempfile.TemporaryDirectory() as build:
            table = os.path.join(build, 'partition_table/partition-table.bin')
            os.makedirs(os.path.dirname(table), exist_ok=True)
            with open(table, 'wb') as f:
                f.write(b'old' + _pt4m_table()[3:])
            result = subprocess.CompletedProcess([], 0, '', '')
            with patch.object(flash.subprocess, 'run', return_value=result) as run:
                with self.assertRaises(FlashError):
                    flash.verify_device_partition_table('esptool', 'esp32c3',
                                                        '/dev/fake', build)
                run.assert_not_called()

    def test_field_bundle_refuses_blank_rlcfg_before_write(self):
        board = SimpleNamespace(chip='esp32c6', flash_baud=115200)

        def read_flash(cmd, **_kwargs):
            with open(cmd[-1], 'wb') as fh:
                fh.write(b'\xff' * flash.RLCFG_SIZE)
            return subprocess.CompletedProcess(cmd, 0, '', '')
        with tempfile.TemporaryDirectory() as out, \
                patch.object(flash, 'preflight_board', return_value={}), \
                patch.object(flash.subprocess, 'run', side_effect=read_flash) as run, \
                patch.object(flash, 'build_write_flash_cmd') as write:
            with self.assertRaisesRegex(FlashError, 'rlcfg is blank'):
                flash._flash_board_from_dir(board, '/dev/fake', out, 'esptool',
                                            False, 0, 1, out, needs_config=True)
            self.assertIn('read-flash', run.call_args.args[0])
            write.assert_not_called()

    def test_only_generic_field_bundles_need_config(self):
        field = 'CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y\n'
        setup = field + 'CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y\n'
        self.assertTrue(flash.field_bundle_needs_config({'generic_config': True}, field))
        self.assertFalse(flash.field_bundle_needs_config({'generic_config': True}, setup))
        self.assertFalse(flash.field_bundle_needs_config({'generic_config': False}, field))


if __name__ == '__main__':
    unittest.main()
