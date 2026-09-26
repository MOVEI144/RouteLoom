"""App-only upgrades must not overwrite board, secret or security state."""

import csv
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


class BoardPartitionTest(unittest.TestCase):
    def test_app_upgrade_preserves_individual_state(self):
        for role in ("bridge_node", "reference_node"):
            with self.subTest(role=role):
                with (ROOT / "firmware" / role / "partitions.csv").open() as source:
                    entries = {
                        row[0].strip(): (row[1].strip(), row[2].strip(),
                                         int(row[3].strip(), 0), int(row[4].strip(), 0))
                        for row in csv.reader(line for line in source if not line.startswith("#"))
                    }
                self.assertEqual(entries["rlcfg"], ("data", "nvs", 0x1B0000, 0x6000))
                self.assertEqual(entries["rlkeys"], ("data", "nvs", 0x1B6000, 0x3000))
                factory = entries["factory"]
                self.assertEqual(factory, ("app", "factory", 0x10000, 0x180000))
                app_end = factory[2] + factory[3]
                for name in ("rlsec", "rlcfg", "rlkeys"):
                    self.assertGreaterEqual(entries[name][2], app_end)
                self.assertGreaterEqual(entries["rlcfg"][2], entries["rlsec"][2] + entries["rlsec"][3])
                self.assertEqual(entries["rlkeys"][2], entries["rlcfg"][2] + entries["rlcfg"][3])
                self.assertLessEqual(entries["rlkeys"][2] + entries["rlkeys"][3], 0x200000)


if __name__ == "__main__":
    unittest.main()
