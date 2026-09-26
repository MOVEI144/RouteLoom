"""D00 baseline contracts: profile names/values and their maturity.

Guards the three-axis (security/routing/resource) contract so main, PR,
and proposal claims stay distinguishable, and pins the capabilities
compatibility policy to the spec text.
"""
import json
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
MATURITY = {'main', 'pr', 'proposal'}


class MeshProfilesTests(unittest.TestCase):
    def test_axes_and_value_names(self):
        profiles = json.loads((ROOT / 'docs/reference/mesh-profiles.json').read_text())
        self.assertEqual(profiles['schema_version'], 1)
        self.assertEqual(set(profiles['axes']), {'security', 'routing', 'resource'})
        security = profiles['axes']['security']['values']
        self.assertIn('DEV_RAM', security)
        self.assertIn('MEMBER_EDHOC', security)
        routing = profiles['axes']['routing']['values']
        self.assertEqual(set(routing), {'FLAT', 'GATEWAY_SCOPED'})
        resource = profiles['axes']['resource']['values']
        budgeted = json.loads((ROOT / 'docs/reference/resource-profiles.json').read_text())
        self.assertEqual(set(resource), set(budgeted['profiles']))

    def test_every_value_names_maturity_and_evidence(self):
        profiles = json.loads((ROOT / 'docs/reference/mesh-profiles.json').read_text())
        for axis, body in profiles['axes'].items():
            for name, value in body['values'].items():
                self.assertIn(value['maturity'], MATURITY, f'{axis}/{name}')
                self.assertTrue(value['evidence'], f'{axis}/{name} needs evidence paths')
                for path in value['evidence']:
                    self.assertTrue((ROOT / path).exists(), f'{axis}/{name}: {path}')

    def test_capabilities_policy_is_pinned_in_spec(self):
        host = (ROOT / 'docs/spec/host.md').read_text(encoding='utf-8')
        self.assertIn('caps_version', host)
        self.assertIn('additive-only', host)
        self.assertIn('ignore unknown', host)


if __name__ == '__main__':
    unittest.main()
