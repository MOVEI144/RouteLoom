"""Boundary checks for generated references, API1 fixtures and atomic consumer storage."""
import importlib.util
import json
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from gen_user_reference import outputs
from check_api1_contract import check
import check_api1_contract
from api1_mock.daemon import response

spec = importlib.util.spec_from_file_location('display_consumer', ROOT / 'examples/display_consumer/consumer.py')
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class UserDocumentationTests(unittest.TestCase):
    def test_public_headers_are_doxygen_inputs(self):
        config = (ROOT / 'tools/Doxyfile').read_text()
        directories = re.search(r'^INPUT\s*=\s*(.*)$', config, re.MULTILINE).group(1).split()
        inputs = {path for directory in directories for path in (ROOT / directory).glob('*')}
        public = {p for p in (ROOT / 'components').glob('*/include/routeloom/*')
                  if p.suffix in ('.h', '.hpp')}
        self.assertEqual(public - inputs, set())

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

    def test_contract_checker_rejects_inconsistent_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / 'protocol/api1'
            (base / 'fixtures').mkdir(parents=True)
            for schema in (ROOT / 'protocol/api1').glob('*.schema.json'):
                (base / schema.name).write_text(schema.read_text())
            for field, value in [('payload_len', 2), ('network', '00000000524c0002')]:
                case = json.loads((ROOT / 'protocol/api1/fixtures/read.json').read_text())
                case['response']['result']['records'][0][field] = value
                (base / 'fixtures/read.json').write_text(json.dumps(case))
                with self.subTest(field=field), patch.object(check_api1_contract, 'ROOT', root):
                    with self.assertRaises(ValueError):
                        check()

    def test_mock_rejects_non_contract_json(self):
        case = json.loads((ROOT / 'protocol/api1/fixtures/read.json').read_text())
        body = json.dumps(case['request'], separators=(',', ':'))
        reply = response(b'API1 ' + (body + '\n').encode('utf-16-be'), [case])
        self.assertEqual(reply['error']['code'], 'INVALID_REQUEST')
        for invalid in (body.replace('"v":1', '"v":true'),
                        body.replace('"v":1', '"v":1.0'),
                        body.replace('"v":1', '"v":1,"v":1'),
                        body.replace('"limit":32', '"limit":NaN'),
                        body.replace('"limit":32', '"limit":' + '[' * 8 + '0' + ']' * 8)):
            with self.subTest(body=invalid):
                reply = response(b'API1 ' + invalid.encode() + b'\n', [case])
                self.assertEqual(reply['error']['code'], 'INVALID_REQUEST')

    def test_failed_explicit_resume_preserves_durable_cursor(self):
        case = json.loads((ROOT / 'protocol/api1/fixtures/read.json').read_text())
        network = case['request']['params']['network']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'consumer.db'
            db = consumer.open_db(path)
            consumer.save_batch(db, network, case['response']['result'])
            db.close()
            argv = ['consumer', '--socket', '/unused', '--network', network,
                    '--db', str(path), '--once', '--resume-cursor', 'invalid-cursor']
            with patch.object(sys, 'argv', argv), patch.object(consumer, 'poll', side_effect=ValueError('INVALID_CURSOR')):
                self.assertEqual(consumer.main(), 1)
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT cursor FROM cursors').fetchone()[0],
                                 case['response']['result']['next_cursor'])

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
