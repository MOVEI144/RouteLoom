"""Boot-path ordering contracts that cannot be exercised by host IDF stubs."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeviceBootOrderTests(unittest.TestCase):
    def test_fail_streak_is_initialized_before_task_creation_can_fail(self):
        source = (ROOT / "components/routeloom_device/src/device_esp.cpp").read_text()
        start = source.split("void Device::start(", 1)[1].split("void Device::task_entry(", 1)[0]
        self.assertIn("fail_streak_boot(s_fail);", start)
        self.assertLess(start.index("fail_streak_boot(s_fail);"), start.index("xTaskCreate("))


if __name__ == "__main__":
    unittest.main()
