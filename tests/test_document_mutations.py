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

class MutationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'repo'
        shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','__pycache__','validation'))
    def tearDown(self): self.temp.cleanup()
    def change_json(self,path,edit):
        p=self.root/path; data=json.loads(p.read_text()); edit(data); p.write_text(json.dumps(data,ensure_ascii=False)+'\n')
    def rejected(self): self.assertTrue(validate(self.root)['failed'])
    def test_valid_source_passes(self): self.assertEqual(validate(self.root)['failed'],[])
    def test_original_review_latency_mutation(self):
        p=self.root/'docs/spec/acceptance.md'; s=p.read_text(); self.assertIn('P95 20ms以内',s); p.write_text(s.replace('P95 20ms以内','P95 2ms以内',1)); self.rejected()
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

if __name__=='__main__': unittest.main()
