"""App-only upgrades must not overwrite board, secret or security state."""

import unittest
from pathlib import Path

from routeloom_meshviz import firmware_catalog as catalog

ROOT = Path(__file__).resolve().parents[3]


class BoardPartitionTest(unittest.TestCase):
    def test_shared_field_boot_uses_verified_identity(self):
        boot = (ROOT / "components/routeloom_device/src/device_esp.cpp").read_text()
        device = (ROOT / "components/routeloom_device/src/device.cpp").read_text()
        # The gate runs before begin(), which alone starts the Owner and RF.
        gate = boot.index("resolve_field_identity(board_stores.config()")
        self.assertLess(gate, boot.index("status = begin(config"))
        self.assertLess(device.index("Status Device::begin("), device.index("owner.begin("))
        for binding in (
            "config.radio.node.node = board.node;",
            "config.radio.node.network = board.network;",
            "config.radio.channel = board.channel;",
            "config.dev_psk = board_secrets->psk;",
        ):
            with self.subTest(binding=binding):
                self.assertIn(binding, boot)

    def test_app_upgrade_preserves_individual_state(self):
        for role in ("bridge_node", "reference_node", "bench_node"):
            with self.subTest(role=role):
                table = (ROOT / "firmware" / role / "partitions.csv").read_bytes()
                # The shipped table is the PT-4M-v2 layout the bundles sign.
                catalog._check_partition_csv(table, role)
                persistent = [row for row in catalog.PT_4M_V2
                              if row[0] in ("nvs", "rlsec", "rlcfg", "rlkeys")]
                for offset in catalog.APP_ONLY_OFFSETS:
                    size = {row[3]: row[4] for row in catalog.PT_4M_V2}[offset]
                    for name, _, _, start, length in persistent:
                        self.assertTrue(offset + size <= start or start + length <= offset,
                                        (offset, name))

if __name__ == "__main__":
    unittest.main()
