"""Keep the recovery design aligned with the implemented wire profile."""

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class RecoveryDesignTests(unittest.TestCase):
    def test_recovery_and_trust_paths_match_wire_contract(self):
        design = (ROOT / "docs/design/scope-gateway-config/04-remote-config.md").read_text()
        wire = (ROOT / "docs/design/scope-gateway-config/05-wire-api.md").read_text()
        self.assertIn("RCR2", wire)
        self.assertIn("RCR2", design)
        self.assertNotIn("RCR1 recovery object", design)
        self.assertIn("RTM1", wire)
        self.assertIn("RTM1", design)
        self.assertNotIn("`AuthorityGeneration`", design)


if __name__ == "__main__":
    unittest.main()
