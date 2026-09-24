"""Keep every SDK v1 golden-vector generator in the SDK CI regeneration gate."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SdkV1VectorCiTests(unittest.TestCase):
    def test_all_sdkv1_generators_run_in_sdk_ci(self):
        workflow = (ROOT / ".github/workflows/sdk.yml").read_text()
        generators = sorted((ROOT / "tools").glob("gen_sdkv1*_vectors.py"))
        self.assertTrue(generators)
        for generator in generators:
            with self.subTest(generator=generator.name):
                self.assertIn(f"python3 tools/{generator.name}", workflow)


if __name__ == "__main__":
    unittest.main()
