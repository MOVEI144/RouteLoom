"""NVS entry budget model for issue #37 (sdk-v1/05 §5.3, V1-N07).

Arithmetic over the repository's headers and partition tables plus negative
mutations; no device, flash or ESP-IDF build is involved.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import nvs_budget  # noqa: E402

SOURCES = nvs_budget.load_sources(ROOT)


def failed_names(sources):
    return {item["name"] for item in nvs_budget.run(sources)["failed"]}


class RepositoryBudget(unittest.TestCase):
    def test_repository_passes(self):
        result = nvs_budget.run(SOURCES)
        self.assertEqual(result["failed"], [])
        self.assertEqual(result["entries_per_peer"], 20)

    def test_design_numbers(self):
        apps = {app["app"]: app for app in nvs_budget.run(SOURCES)["apps"]}
        node = apps["firmware/reference_node"]
        gateway = apps["firmware/bridge_node"]
        # 05 §5.2: 64 KiB -> 15 x 126 usable entries, 128 KiB -> 31 x 126.
        self.assertEqual((node["partition_bytes"], node["usable_entries"]), (0x10000, 1890))
        self.assertEqual((gateway["partition_bytes"], gateway["usable_entries"]), (0x20000, 3906))
        self.assertEqual(node["max_persisted_peers"], 64)
        self.assertEqual(gateway["max_persisted_peers"], 128)
        self.assertEqual(apps["examples/espnow_node"]["max_persisted_peers"], 64)
        for app in apps.values():
            self.assertLessEqual(app["worst_case_entries"], app["budget_entries"])

    def test_blob_entry_formula(self):
        self.assertEqual(nvs_budget.blob_entries(32, 32), 3)
        self.assertEqual(nvs_budget.blob_entries(24, 32), 3)
        self.assertEqual(nvs_budget.blob_entries(40, 32), 4)

    def test_cpp_formula_mirror(self):
        constants = nvs_budget.load_constants(SOURCES)
        self.assertEqual(nvs_budget.max_peers_for_entries(16 * 126, constants), 75)
        self.assertEqual(nvs_budget.max_peers_for_entries(32 * 126, constants), 156)
        self.assertEqual(nvs_budget.max_peers_for_entries(126, constants), 0)


class NegativeMutations(unittest.TestCase):
    def mutate(self, key, old, new):
        sources = dict(SOURCES)
        self.assertIn(old, sources[key])
        sources[key] = sources[key].replace(old, new, 1)
        return sources

    def test_cap_over_budget_fails(self):
        sources = self.mutate("provider", "kNodeMaxPersistedPeers = 64",
                              "kNodeMaxPersistedPeers = 90")
        self.assertIn("firmware/reference_node:worst_case_within_budget",
                      failed_names(sources))

    def test_small_partition_fails(self):
        sources = self.mutate("firmware/bridge_node/partitions.csv",
                              "0x190000, 0x20000", "0x190000, 0x10000")
        failed = failed_names(sources)
        self.assertIn("firmware/bridge_node:worst_case_within_budget", failed)
        self.assertIn("firmware/bridge_node:cap_not_clamped", failed)

    def test_missing_security_partition_fails(self):
        sources = self.mutate("firmware/reference_node/partitions.csv",
                              "rlsec,", "rlsex,")
        self.assertIn("firmware/reference_node:security_nvs_present", failed_names(sources))

    def test_table_beyond_flash_fails(self):
        sources = self.mutate("examples/espnow_node/partitions.csv",
                              "0x190000, 0x10000", "0x1F8000, 0x10000")
        self.assertIn("examples/espnow_node:fits_flash", failed_names(sources))

    def test_overlap_fails(self):
        sources = self.mutate("firmware/reference_node/partitions.csv",
                              "0x190000, 0x10000", "0x180000, 0x10000")
        self.assertIn("firmware/reference_node:no_overlap", failed_names(sources))

    def test_default_table_fails(self):
        sources = self.mutate("firmware/bridge_node/sdkconfig.defaults",
                              "CONFIG_PARTITION_TABLE_CUSTOM=y",
                              "CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y")
        self.assertIn("firmware/bridge_node:custom_table_selected", failed_names(sources))

    def test_record_growth_fails(self):
        sources = self.mutate("replay",
                              "static_assert(sizeof(ReplayWindowRecord) == 40",
                              "static_assert(sizeof(ReplayWindowRecord) == 72")
        self.assertIn("entries_per_peer_matches_codecs", failed_names(sources))

    def test_shrunk_factory_fails(self):
        sources = self.mutate("firmware/reference_node/partitions.csv",
                              "0x10000,  0x180000", "0x10000,  0x100000")
        self.assertIn("firmware/reference_node:factory_not_shrunk", failed_names(sources))


if __name__ == "__main__":
    unittest.main()
