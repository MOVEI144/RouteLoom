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

    def test_design_numbers(self):
        apps = {app["app"]: app for app in nvs_budget.run(SOURCES)["apps"]}
        node = apps["firmware/reference_node"]
        gateway = apps["firmware/bridge_node"]
        # PT-4M-v2: 128 KiB rlsec for every role -> 31 x 126 usable entries.
        self.assertEqual((node["partition_bytes"], node["usable_entries"]), (0x20000, 3906))
        self.assertEqual((gateway["partition_bytes"], gateway["usable_entries"]), (0x20000, 3906))
        for app in apps.values():
            self.assertLessEqual(app["ram_worst_case_entries"], app["budget_entries"])

    def test_resume_write_budget_mentions_reservations(self):
        design = (ROOT / 'docs/design/sdk-v1/05-nvs-state-37.md').read_text()
        store = (ROOT / 'components/routeloom/src/sdkv1_store.cpp').read_text()
        self.assertIn('年295,663 write', design)
        self.assertIn('年72,777 RLP2 write', design)
        self.assertIn('slot.reserved_uses += quantum', store)
        self.assertIn('budget_next_ = (budget_next_ + 1) % kUseBudgetEntries', store)

    def test_blob_entry_formula(self):
        self.assertEqual(nvs_budget.blob_entries(32, 32), 3)
        self.assertEqual(nvs_budget.blob_entries(24, 32), 3)
        self.assertEqual(nvs_budget.blob_entries(40, 32), 4)


class NegativeMutations(unittest.TestCase):
    def mutate(self, key, old, new):
        sources = dict(SOURCES)
        self.assertIn(old, sources[key])
        sources[key] = sources[key].replace(old, new, 1)
        return sources

    def test_small_partition_fails(self):
        sources = self.mutate("firmware/bridge_node/partitions.csv",
                              "0x20000,  0x20000", "0x20000,  0x4000")
        failed = failed_names(sources)
        self.assertIn("firmware/bridge_node:worst_case_ram_within_budget", failed)
        self.assertIn("firmware/bridge_node:layout_matches_boot_check", failed)

    def test_missing_security_partition_fails(self):
        sources = self.mutate("firmware/reference_node/partitions.csv",
                              "rlsec,", "rlsex,")
        self.assertIn("firmware/reference_node:security_nvs_present", failed_names(sources))

    def test_two_mb_flash_setting_fails(self):
        sources = self.mutate("examples/espnow_node/sdkconfig.defaults",
                              "CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y",
                              "CONFIG_ESPTOOLPY_FLASHSIZE_2MB=y")
        self.assertIn("examples/espnow_node:fits_flash", failed_names(sources))

    def test_eight_mb_flash_setting_fails(self):
        sources = self.mutate("examples/espnow_node/sdkconfig.defaults",
                              "CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y",
                              "CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y")
        self.assertIn("examples/espnow_node:flash_size_4mb", failed_names(sources))

    def test_overlap_fails(self):
        sources = self.mutate("firmware/reference_node/partitions.csv",
                              "0x20000,  0x20000", "0x30000,  0x20000")
        self.assertIn("firmware/reference_node:no_overlap", failed_names(sources))

    def test_rollback_disabled_fails(self):
        sources = self.mutate("firmware/bench_node/sdkconfig.defaults",
                              "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y", "")
        self.assertIn("firmware/bench_node:rollback_enabled", failed_names(sources))

    def test_boot_check_table_drift_fails(self):
        sources = self.mutate("flash_layout", '{"coredump", 1, 3, 0x3E0000, 0x10000}',
                              '{"coredump", 1, 3, 0x3F0000, 0x10000}')
        failed = failed_names(sources)
        for app in nvs_budget.APPS:
            self.assertIn(f"{app}:layout_matches_boot_check", failed)

    def test_default_table_fails(self):
        sources = self.mutate("firmware/bridge_node/sdkconfig.defaults",
                              "CONFIG_PARTITION_TABLE_CUSTOM=y",
                              "CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y")
        self.assertIn("firmware/bridge_node:custom_table_selected", failed_names(sources))

    def test_resume_quota_growth_fails(self):
        sources = self.mutate("store", "kResume2GatewayLinkQuota = ",
                              "kResume2GatewayLinkQuota = 9")
        self.assertIn("firmware/bridge_node:worst_case_ram_within_budget",
                      failed_names(sources))

    def test_factory_app_fails(self):
        sources = self.mutate("firmware/reference_node/partitions.csv",
                              "ota_0,    app,  ota_0,", "ota_0,    app,  factory,")
        self.assertIn("firmware/reference_node:ota_slots", failed_names(sources))

    def test_partition_subtype_drift_fails(self):
        sources = self.mutate("firmware/reference_node/partitions.csv",
                              "coredump, data, coredump,", "coredump, data, nvs,")
        self.assertIn("firmware/reference_node:layout_matches_boot_check",
                      failed_names(sources))


if __name__ == "__main__":
    unittest.main()
