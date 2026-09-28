"""Private rlsec backups must never be placed under the source tree."""

import pathlib
import hashlib
import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import reprovision_reset
import restore_rlsec


def board_for(build):
    return SimpleNamespace(name='ref-a', app='reference_node', chip='esp32c3',
                           mac='94:a9:90:7a:b5:60', build_dir=lambda repo: str(build))


class ReprovisionResetTest(unittest.TestCase):
    def test_private_backup_rejects_repository_directory(self):
        repo = pathlib.Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(dir=repo) as directory:
            with self.assertRaises(ValueError):
                reprovision_reset.private_backup_path(
                    str(pathlib.Path(directory) / "rlsec.bin"))

    def test_audited_rlsec_region_matches_partition_tables(self):
        repo = pathlib.Path(__file__).resolve().parents[2]
        for app, size in reprovision_reset.RLSEC_SIZES.items():
            table = (repo / f"firmware/{app}/partitions.csv").read_text()
            self.assertTrue(reprovision_reset.rlsec_row_matches(table, size), app)

    def test_old_device_table_refuses_before_erase(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            private = root / 'private'
            private.mkdir(mode=0o700)
            board = board_for(root / 'build')
            rig = {'bench': SimpleNamespace(boards={'ref-a': board})}
            argv = ['reprovision_reset.py', '--rig', 'rig', '--bench', 'bench',
                    '--board', 'ref-a', '--backup', str(private / 'rlsec.bin'),
                    '--out', str(root / 'out')]
            with patch.object(sys, 'argv', argv), \
                    patch.object(reprovision_reset.rig, 'load_rigs', return_value=rig), \
                    patch.object(reprovision_reset.rig, 'resolve_board_port',
                                 return_value=('/dev/fake', [], 'ONLINE')), \
                    patch.object(reprovision_reset.flash, 'preflight_board', return_value={}), \
                    patch.object(reprovision_reset.flash, 'verify_device_partition_table',
                                 side_effect=reprovision_reset.flash.FlashError('old table')), \
                    patch.object(reprovision_reset.subprocess, 'run') as run:
                with self.assertRaises(reprovision_reset.flash.FlashError):
                    reprovision_reset.main()
                run.assert_not_called()

    def test_old_device_table_refuses_before_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            private = root / 'private'
            private.mkdir(mode=0o700)
            backup = private / 'rlsec.bin'
            backup.write_bytes(b'\xff' * 0x20000)
            board = board_for(root / 'build')
            rig = {'bench': SimpleNamespace(boards={'ref-a': board})}
            manifest = root / 'backup.json'
            manifest.write_text(json.dumps({
                'board': board.name, 'chip': board.chip, 'mac': board.mac,
                'offset': '0x20000', 'size': '0x20000', 'erased': True,
                'backup_path': str(backup),
                'backup_sha256': hashlib.sha256(backup.read_bytes()).hexdigest()}))
            argv = ['restore_rlsec.py', '--rig', 'rig', '--bench', 'bench',
                    '--board', 'ref-a', '--manifest', str(manifest),
                    '--out', str(root / 'out')]
            with patch.object(sys, 'argv', argv), \
                    patch.object(restore_rlsec.rig, 'load_rigs', return_value=rig), \
                    patch.object(restore_rlsec.rig, 'resolve_board_port',
                                 return_value=('/dev/fake', [], 'ONLINE')), \
                    patch.object(restore_rlsec.flash, 'preflight_board', return_value={}), \
                    patch.object(restore_rlsec.flash, 'verify_device_partition_table',
                                 side_effect=restore_rlsec.flash.FlashError('old table')), \
                    patch.object(restore_rlsec.subprocess, 'run') as run:
                with self.assertRaises(restore_rlsec.flash.FlashError):
                    restore_rlsec.main()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
