"""Keep the experimental C6 build compatible with its component search path."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class C6ComponentContractTest(unittest.TestCase):
    def test_every_scanned_component_manifest_accepts_c6(self):
        workflow = (ROOT / ".github/workflows/sdk.yml").read_text(encoding="utf-8")
        self.assertIn("idf.py set-target esp32c6", workflow)

        for app in ("bridge_node", "reference_node"):
            cmake = (ROOT / "firmware" / app / "CMakeLists.txt").read_text(
                encoding="utf-8"
            )
            self.assertIn('../../components"', cmake)

        for manifest in (ROOT / "components").glob("*/idf_component.yml"):
            text = manifest.read_text(encoding="utf-8")
            targets = text.partition("\ntargets:\n")[2].partition("\ndependencies:\n")[0]
            if targets:
                with self.subTest(component=manifest.parent.name):
                    self.assertIn("  - esp32c6", targets.splitlines())


if __name__ == "__main__":
    unittest.main()
