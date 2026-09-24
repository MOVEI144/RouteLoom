"""Mutate temporary copies only, and require the document checker to fail."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from check_review_contracts import validate
from check_docs import run as docs_run

class MutationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'repo'
        shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','__pycache__','validation'))
    def tearDown(self): self.temp.cleanup()
    def change_json(self,path,edit):
        p=self.root/path; data=json.loads(p.read_text()); edit(data); p.write_text(json.dumps(data,ensure_ascii=False)+'\n')
    def rejected(self): self.assertTrue(validate(self.root)['failed'])
    def docs_rejected(self): self.assertTrue(docs_run(self.root)['failed'])
    def test_valid_source_passes(self): self.assertEqual(validate(self.root)['failed'],[])
    def test_original_review_latency_mutation(self):
        p=self.root/'docs/spec/acceptance.md'; s=p.read_text(); self.assertIn('P95 35ms以内',s); p.write_text(s.replace('P95 35ms以内','P95 2ms以内',1)); self.rejected()
    def test_latency_target_below_airtime_floor_mutation(self):
        # Issue #47: a doc-consistent target below the LR250 serial floor must
        # still be rejected by the contract invariant.
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['performance_targets_ms'].update(reliable_1hop_p95=10)); self.rejected()
    def test_latency_floor_understated_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor']['floor_ms'].update(reliable_10hop_p95=100)); self.rejected()
    def test_latency_floor_overstated_mutation(self):
        # floor_ms must equal ceil(derived model), not merely bound it.
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor']['floor_ms'].update(reliable_10hop_p95=400)); self.rejected()
    def test_latency_wire_bytes_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor']['frame_wire_bytes'].update(data_64b_payload=200)); self.rejected()
    def test_latency_us_per_byte_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor'].update(us_per_byte=16)); self.rejected()
    def test_latency_mac_overhead_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor'].update(espnow_mac_overhead_bytes=20)); self.rejected()
    def test_latency_preamble_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor'].update(lr_preamble_model_ms=0.30)); self.rejected()
    def test_latency_preamble_out_of_range_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor'].update(lr_preamble_model_ms=1.0)); self.rejected()
    def test_latency_turnaround_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor'].update(relay_turnaround_ms=1.0)); self.rejected()
    def test_latency_airtime_hand_edit_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['latency_floor']['frame_airtime_ms'].update(data=5.0)); self.rejected()
    def test_latency_coordinated_bit_rate_mutation(self):
        # Issue #47 review: an internally consistent edit (premise + derived
        # airtime + displayed floor + target moved together) must still fail
        # because bit time is pinned to the 250kbps contract, not declared.
        def mutate(d):
            m=d['latency_floor']
            m['us_per_byte']=16
            m['frame_airtime_ms'].update(data=4.13,hop_accept=3.2,end_receipt=3.58)
            m['floor_ms'].update(reliable_1hop_p95=19,reliable_5hop_p95=115,reliable_10hop_p95=236)
            d['performance_targets_ms'].update(reliable_1hop_p95=20)
        self.change_json('docs/reference/radio-defaults.json',mutate); self.rejected()
    def test_latency_coordinated_mac_overhead_mutation(self):
        # Overhead 20B with consistent recomputation: still pinned to the
        # ESP-NOW constant and the Wire v1 frame layouts.
        def mutate(d):
            m=d['latency_floor']
            m['espnow_mac_overhead_bytes']=20
            m['frame_airtime_ms'].update(data=7.02,hop_accept=5.16,end_receipt=5.93)
            m['floor_ms'].update(reliable_1hop_p95=26,reliable_5hop_p95=159,reliable_10hop_p95=326)
        self.change_json('docs/reference/radio-defaults.json',mutate); self.rejected()
    def test_latency_coordinated_wire_length_mutation(self):
        # Shrinking the declared DATA wire length with consistent airtime/
        # floor recomputation must fail — lengths match wire.hpp constants.
        def mutate(d):
            m=d['latency_floor']
            m['frame_wire_bytes']['data_64b_payload']=120
            m['frame_airtime_ms'].update(data=5.71)
            m['floor_ms'].update(reliable_1hop_p95=26,reliable_5hop_p95=163,reliable_10hop_p95=334)
        self.change_json('docs/reference/radio-defaults.json',mutate); self.rejected()
    def test_decisions_stale_hop_target_mutation(self):
        # decisions.md must track the manifest's current 1hop target —
        # re-adding the pre-#47 value is prose drift, not a valid history.
        p=self.root/'docs/spec/decisions.md'; s=p.read_text()
        self.assertIn('1hop35ms目標',s)
        p.write_text(s.replace('1hop35ms目標','1hop20ms目標',1)); self.docs_rejected()
    def test_original_review_pin_mutation(self):
        p=self.root/'docs/hardware/xiao-esp32c3.md'; s=p.read_text(); self.assertIn('| D4 | 6 |',s); p.write_text(s.replace('| D4 | 6 |','| D4 | 12 |',1)); self.rejected()
    def test_original_review_commit_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['esp_idf'].update(commit='0'*40)); self.rejected()
    def test_unqualified_auto_migration_mutation(self):
        self.change_json('docs/reference/radio-defaults.json',lambda d:d['migration'].update(auto_policy=True)); self.rejected()
    def test_nonmember_data_mutation(self):
        self.change_json('protocol/semantics.json',lambda d:d['membership_allowlist']['DISCOVERING'].append('DATA')); self.rejected()
    def test_c5_unqualified_runtime_mutation(self):
        self.change_json('docs/reference/boards.json',lambda d:d['boards'][2].update(runtime_generation_allowed=True)); self.rejected()
    def test_unmeasured_memory_mutation(self):
        self.change_json('docs/reference/resource-profiles.json',lambda d:d['profiles']['relay-c3']['budget_bytes'].update(statistics_pool=10**6)); self.rejected()
    def test_additive_credit_mutation(self):
        self.change_json('protocol/semantics.json',lambda d:d.update(usb_credit='additive-delta')); self.rejected()

    def test_end_aad_drops_type_mutation(self):
        self.change_json('protocol/semantics.json',lambda d:d.update(end_aad_fields=[f for f in d['end_aad_fields'] if f['field']!='type'])); self.rejected()
    def test_end_aad_hop_mutable_mutation(self):
        self.change_json('protocol/semantics.json',lambda d:d['end_aad_fields'].append({'field':'next_hop','bytes':8})); self.rejected()
if __name__=='__main__': unittest.main()
