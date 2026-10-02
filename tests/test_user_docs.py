"""Boundary checks for generated references, API1 fixtures and atomic consumer storage."""
import importlib.util
import json
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from gen_user_reference import outputs
from check_api1_contract import check
from api1_mock.daemon import response

spec = importlib.util.spec_from_file_location('display_consumer', ROOT / 'examples/display_consumer/consumer.py')
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class UserDocumentationTests(unittest.TestCase):
    def test_generated_references_and_api1_fixtures(self):
        for path, expected in outputs(ROOT).items():
            self.assertEqual((ROOT / path).read_text(), expected, path)
        check()

    def test_mock_replays_fixture_and_rejects_invalid_envelope(self):
        case = json.loads((ROOT / 'protocol/api1/fixtures/read.json').read_text())
        line = b'API1 ' + json.dumps(case['request']).encode() + b'\n'
        self.assertEqual(response(line, [case]), case['response'])
        invalid = dict(case['request'], v=2)
        reply = response(b'API1 ' + json.dumps(invalid).encode() + b'\n', [case])
        self.assertEqual(reply['error']['code'], 'INVALID_REQUEST')

    def test_commit_and_failure_keep_record_cursor_together(self):
        case = json.loads((ROOT / 'protocol/api1/fixtures/read.json').read_text())
        with consumer.open_db(Path(':memory:')) as db:
            network = case['request']['params']['network']
            result = case['response']['result']
            consumer.save_batch(db, network, result)
            consumer.save_batch(db, network, result)
            self.assertEqual(db.execute('SELECT count(*) FROM records').fetchone()[0], 1)
            db.execute("CREATE TRIGGER reject_cursor BEFORE UPDATE ON cursors BEGIN SELECT RAISE(ABORT,'disk failure'); END")
            altered = json.loads(json.dumps(result))
            altered['records'][0]['message']['sequence'] = '0000000000000002'
            altered['next_cursor'] = 'new-position'
            with self.assertRaises(sqlite3.Error):
                consumer.save_batch(db, network, altered)
            self.assertEqual(db.execute('SELECT count(*) FROM records').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT cursor FROM cursors').fetchone()[0], result['next_cursor'])


if __name__ == '__main__':
    unittest.main()
