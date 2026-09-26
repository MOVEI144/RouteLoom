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


if __name__ == "__main__":
    unittest.main()
