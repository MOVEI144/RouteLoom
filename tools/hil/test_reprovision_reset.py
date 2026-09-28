"""Private rlsec backups must never be placed under the source tree."""

import pathlib
import tempfile
import unittest

import reprovision_reset


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


if __name__ == "__main__":
    unittest.main()
