import hashlib
import json
from copy import deepcopy
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from routeloom_meshviz.model import FakeClock, State, reduce, route_hops
from routeloom_meshviz.capture import Capture, replay
from routeloom_meshviz.fake_api1 import FakeAPI1, serve_fake_api1
from routeloom_meshviz.device import (Identity, Port, reconcile, PortLeases,
                                     Image, FlashPlan, run_batch, import_rig)
from routeloom_meshviz.flash_worker import flash


class ModelTests(unittest.TestCase):
    def test_fake_clock_keeps_integer_monotonic_and_wall_time(self):
        clock = FakeClock()
        with self.assertRaises(ValueError):
            clock.advance(0.5)
        with self.assertRaises(ValueError):
            clock.jump_unix(float('nan'))
        self.assertEqual((clock.mono_ns, clock.unix_ms), (0, 0))

    def test_event_capture_replay_unknown_gap_boot_clock_jump(self):
        clock = FakeClock(1_000_000_000, 1000)
        events = [
            dict(kind='snapshot', scope='site-1', source='daemon', source_epoch='a', source_seq=1,
                 payload={'complete': True, 'nodes': [{'node': '02', 'connected': None, 'boot': 'a'}]}),
            dict(kind='snapshot', scope='site-1', source='daemon', source_epoch='a', source_seq=2,
                 payload={'complete': False, 'nodes': []}),
            dict(kind='gap', source='daemon', source_epoch='a', source_seq=3, payload={'lost': 2}),
            dict(kind='node', scope='site-1', source='daemon', source_epoch='a', source_seq=4,
                 payload={'node': '02', 'connected': True, 'boot': 'b'}),
            dict(kind='node', scope='site-1', source='daemon', source_epoch='a', source_seq=5,
                 payload={'node': '02', 'connected': False, 'boot': 'a'}),
        ]
        with tempfile.TemporaryDirectory() as td:
            live = State()
            with Capture(Path(td) / 'test.rlcapture', 'capture-1') as cap:
                for e in events:
                    clock.advance(100)
                    cap.add(e, clock)
                    reduce(live, e)
                clock.jump_unix(-5000)
                adjustment = {'kind': 'clock_adjustment', 'source': 'clock', 'payload': {'delta_ms': -5000}}
                cap.add(adjustment, clock)
                reduce(live, adjustment)
            recovered = replay(Path(td) / 'test.rlcapture')
            self.assertEqual(live, recovered)
            self.assertEqual(recovered.nodes['site-1:02']['boot'], 'b')
            self.assertIsNone(replay(Path(td) / 'test.rlcapture', until_seq=1).nodes['site-1:02']['connected'])
            self.assertEqual(len(recovered.gaps), 1)
            self.assertEqual(recovered.clock_adjustments, [-5000])

    def test_checkpoint_seek_and_uncommitted_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            clock = FakeClock()
            cap = Capture(path, 'id')
            for seq in range(1, 5002):
                clock.advance(1)
                cap.add({'source': 'daemon', 'source_epoch': 'a', 'source_seq': seq,
                         'scope': 's', 'kind': 'node', 'payload': {'node': '02', 'boot': 'a', 'count': seq}}, clock)
            cap.close()
            with sqlite3.connect(path / 'data.sqlite') as db:
                self.assertEqual(db.execute('SELECT seq FROM checkpoints').fetchall(), [(5000,)])
                # A seek after the checkpoint must not depend on parsing earlier events.
                db.execute('UPDATE events SET payload_json=? WHERE seq=1', ('{"schema_version":99}',))
            self.assertEqual(replay(path, until_seq=5001).nodes['s:02']['count'], 5001)
            with self.assertRaises(ValueError):
                replay(path, until_seq=1)

    def test_unclean_capture_keeps_committed_prefix(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            cap = Capture(path, 'id')
            cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                     'payload': {'node': '02'}}, FakeClock(900_000_000_000))
            self.assertEqual(cap.db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0], 0)
            cap.flush()
            # Simulate abrupt termination: no clean close or final manifest update.
            cap.db.close()
            recovered = replay(path)
            self.assertIn('s:02', recovered.nodes)
            self.assertEqual(recovered.gaps[-1]['reason'], 'UncleanEnd')

    def test_disk_failure_does_not_mark_capture_clean(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            cap = Capture(path, 'id')
            clock = FakeClock()
            cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                     'payload': {'node': '02'}}, clock)
            cap.flush()
            cap.db.execute("CREATE TRIGGER disk_failure BEFORE INSERT ON events "
                           "BEGIN SELECT RAISE(FAIL, 'disk full'); END")
            with self.assertRaises(sqlite3.DatabaseError):
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '03'}}, clock)
            with self.assertRaises(RuntimeError):
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '04'}}, clock)
            cap.close()
            self.assertFalse(json.loads((path / 'manifest.json').read_text())['closed'])
            state = replay(path)
            self.assertEqual(set(state.nodes), {'s:02'})
            self.assertEqual(state.gaps[-1]['reason'], 'UncleanEnd')

    def test_idle_capture_commits_without_more_events(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            cap = Capture(path, 'id')
            try:
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '02'}}, FakeClock())
                deadline = time.monotonic() + 2.5
                committed = 0
                while time.monotonic() < deadline and not committed:
                    with sqlite3.connect(path / 'data.sqlite') as reader:
                        committed = reader.execute('SELECT COUNT(*) FROM events').fetchone()[0]
                    if not committed:
                        time.sleep(0.05)
                self.assertEqual(committed, 1)
                self.assertFalse(json.loads((path / 'manifest.json').read_text())['closed'])
            finally:
                cap.close()

    def test_capture_rejects_unknown_event_schema_before_recording(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            with Capture(path, 'id') as cap:
                with self.assertRaises(ValueError):
                    cap.add({'schema_version': 2, 'source': 'daemon', 'scope': 's',
                             'kind': 'node', 'payload': {'node': '02'}}, FakeClock())
                self.assertEqual(cap.seq, 0)
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '03'}}, FakeClock())
            self.assertEqual(set(replay(path).nodes), {'s:03'})

    def test_corrupt_checkpoint_schema_cannot_bypass_version_check(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            clock = FakeClock()
            with Capture(path, 'id') as cap:
                for seq in range(1, 5001):
                    cap.add({'source': 'daemon', 'scope': 's', 'source_seq': seq,
                             'kind': 'node', 'payload': {'node': '02'}}, clock)
            with sqlite3.connect(path / 'data.sqlite') as db:
                data = json.loads(db.execute('SELECT state_json FROM checkpoints').fetchone()[0])
                data['schema_version'] = 2
                db.execute('UPDATE checkpoints SET state_json=?', (json.dumps(data),))
            with self.assertRaises(ValueError):
                replay(path)

    def test_checkpoint_keeps_unknown_additive_state_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            clock = FakeClock()
            with Capture(path, 'id') as cap:
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '02'}}, clock)
                clock.advance(30_001)
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '03'}}, clock)
            with sqlite3.connect(path / 'data.sqlite') as db:
                data = json.loads(db.execute('SELECT state_json FROM checkpoints').fetchone()[0])
                data['future_metadata'] = {'label': 'preserve me'}
                db.execute('UPDATE checkpoints SET state_json=?', (json.dumps(data),))
            state = replay(path)
            self.assertEqual(state.extensions['future_metadata'], {'label': 'preserve me'})

    def test_partial_snapshot_and_duplicate_source_sequence(self):
        state = State()
        base = {'scope': 's', 'source': 'daemon', 'source_epoch': 'a'}
        reduce(state, {**base, 'kind': 'snapshot', 'source_seq': 1,
                       'payload': {'complete': True, 'nodes': [{'node': '02', 'connected': None}]}})
        reduce(state, {**base, 'kind': 'snapshot', 'source_seq': 2,
                       'payload': {'complete': False, 'nodes': []}})
        reduce(state, {**base, 'kind': 'node', 'source_seq': 2,
                       'payload': {'node': '02', 'connected': True}})
        self.assertIsNone(state.nodes['s:02']['connected'])
        reduce(state, {**base, 'kind': 'snapshot', 'source_seq': 3,
                       'payload': {'complete': True, 'nodes': []}})
        self.assertEqual(state.nodes, {})

    def test_source_epoch_and_route_loop(self):
        state = State()
        for epoch, seq, node in [('old', 8, '01'), ('new', 1, '02'), ('old', 9, '03')]:
            reduce(state, {'kind': 'node', 'scope': 's', 'source': 'daemon',
                           'source_epoch': epoch, 'source_seq': seq,
                           'payload': {'node': node, 'boot': 'a'}})
        self.assertEqual(set(state.nodes), {'s:02'})
        for observer, hop in [('01', '02'), ('02', '01')]:
            reduce(state, {'kind': 'route', 'scope': 's', 'source': 'daemon',
                           'payload': {'observer': observer, 'destination': '03',
                                       'next_hop': hop, 'boot': 'a', 'valid': True}})
        self.assertEqual(len(state.routes), 2)
        self.assertIsNone(route_hops(state, 's', '01', '03'))

    def test_delayed_old_boot_removal_does_not_erase_new_incarnation(self):
        clock = FakeClock()
        base = {'source': 'daemon', 'source_epoch': 'session', 'scope': 's'}
        events = [
            {**base, 'source_seq': 1, 'kind': 'node', 'payload': {'node': '02', 'boot': 'old'}},
            {**base, 'source_seq': 2, 'kind': 'node', 'payload': {'node': '02', 'boot': 'new'}},
            {**base, 'source_seq': 3, 'kind': 'node',
             'payload': {'node': '02', 'boot': 'old', 'removed': True}},
            {**base, 'source_seq': 4, 'kind': 'route',
             'payload': {'observer': '02', 'destination': '01', 'boot': 'old', 'valid': True}},
            {**base, 'source_seq': 5, 'kind': 'route',
             'payload': {'observer': '02', 'destination': '01', 'boot': 'new', 'valid': True}},
            {**base, 'source_seq': 6, 'kind': 'route',
             'payload': {'observer': '02', 'destination': '01', 'boot': 'old', 'removed': True}},
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'boot.rlcapture'
            with Capture(path, 'boot') as cap:
                for event in events:
                    clock.advance(1)
                    cap.add(event, clock)
            state = replay(path)
            self.assertEqual(state.nodes['s:02']['boot'], 'new')
            self.assertEqual(state.routes['s:02:01']['boot'], 'new')
            self.assertEqual(state, replay(path, until_seq=6))

    def test_removal_from_one_source_keeps_other_source_observation(self):
        state = State()
        for source, boot in [('gateway', 'a'), ('reference-usb', 'a')]:
            reduce(state, {'source': source, 'scope': 's', 'kind': 'node',
                           'payload': {'node': '02', 'boot': boot}})
        reduce(state, {'source': 'gateway', 'scope': 's', 'kind': 'node',
                       'payload': {'node': '02', 'boot': 'a', 'removed': True}})
        self.assertEqual(state.nodes['s:02']['_source'], 'reference-usb')

    def test_removing_latest_source_restores_other_source_claim(self):
        state = State()
        for source, connected in [('gateway', False), ('reference-usb', True)]:
            reduce(state, {'source': source, 'scope': 's', 'kind': 'node',
                           'payload': {'node': '02', 'boot': 'a', 'connected': connected}})
        reduce(state, {'source': 'reference-usb', 'scope': 's', 'kind': 'node',
                       'payload': {'node': '02', 'boot': 'a', 'removed': True}})
        self.assertEqual(state.nodes['s:02']['_source'], 'gateway')
        self.assertFalse(state.nodes['s:02']['connected'])

    def test_source_claims_survive_checkpoint_seek_and_epoch_retirement(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'claims.rlcapture'
            clock = FakeClock()
            gateway = {'source': 'gateway', 'source_epoch': 'g1', 'scope': 's'}
            usb = {'source': 'usb', 'source_epoch': 'u1', 'scope': 's'}
            with Capture(path, 'id') as cap:
                cap.add({**gateway, 'kind': 'node',
                         'payload': {'node': '02', 'boot': 'a', 'connected': False}}, clock)
                cap.add({**usb, 'kind': 'node',
                         'payload': {'node': '02', 'boot': 'a', 'connected': True}}, clock)
                clock.advance(30_001)
                cap.add({**usb, 'kind': 'node',
                         'payload': {'node': '02', 'boot': 'a', 'connected': True}}, clock)
                cap.add({**usb, 'kind': 'node',
                         'payload': {'node': '02', 'boot': 'a', 'removed': True}}, clock)
                self.assertEqual(cap.state.nodes['s:02']['_source'], 'gateway')
                cap.add({**gateway, 'source_epoch': 'g2', 'kind': 'gap',
                         'payload': {'reason': 'Reconnect'}}, clock)
                self.assertNotIn('s:02', cap.state.nodes)
            self.assertEqual(replay(path, until_seq=4).nodes['s:02']['_source'], 'gateway')
            self.assertNotIn('s:02', replay(path).nodes)

    def test_every_seek_matches_ordered_live_state_across_checkpoints(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'seek.rlcapture'
            clock = FakeClock()
            live = State()
            expected = []
            with Capture(path, 'id') as cap:
                for index in range(1, 41):
                    source = 'gateway' if index % 2 else 'usb'
                    epoch = ('g2' if index >= 21 else 'g1') if source == 'gateway' else 'u1'
                    base = {'source': source, 'source_epoch': epoch,
                            'source_seq': index, 'scope': 's'}
                    if index % 7 == 0:
                        event = {**base, 'kind': 'snapshot',
                                 'payload': {'complete': False, 'nodes': []}}
                    elif index % 5 == 0:
                        event = {**base, 'kind': 'gap', 'payload': {'lost': 1}}
                    else:
                        event = {**base, 'kind': 'node',
                                 'payload': {'node': '02', 'boot': 'b' if index > 15 else 'a',
                                             'connected': index % 3 == 0}}
                    clock.advance(1000)
                    cap.add(event, clock)
                    reduce(live, event)
                    expected.append(deepcopy(live))
            for position in range(1, 41):
                self.assertEqual(replay(path, until_seq=position), expected[position - 1])
            self.assertEqual(replay(path), expected[-1])

    def test_unsequenced_epoch_change_retires_old_session_and_samples(self):
        state = State()
        base = {'source': 'daemon', 'scope': 's'}
        reduce(state, {**base, 'source_epoch': 'old', 'source_seq': 8,
                       'kind': 'sample', 'payload': {'series': 'rssi', 'value': -40}})
        reduce(state, {**base, 'source_epoch': 'new', 'kind': 'node',
                       'payload': {'node': '02', 'boot': 'new'}})
        reduce(state, {**base, 'source_epoch': 'old', 'source_seq': 9,
                       'kind': 'node', 'payload': {'node': '03', 'boot': 'old'}})
        self.assertEqual(set(state.nodes), {'s:02'})
        self.assertEqual(state.samples, {})
        self.assertEqual(state.sources['daemon'][0], 'new')

    def test_removal_must_name_current_boot(self):
        state = State()
        base = {'source': 'daemon', 'source_epoch': 'a', 'scope': 's'}
        reduce(state, {**base, 'source_seq': 1, 'kind': 'node',
                       'payload': {'node': '02', 'boot': 'new'}})
        reduce(state, {**base, 'source_seq': 2, 'kind': 'node',
                       'payload': {'node': '02', 'boot': 'unknown', 'removed': True}})
        self.assertEqual(state.nodes['s:02']['boot'], 'new')

    def test_unknown_boot_does_not_downgrade_known_incarnation(self):
        state = State()
        base = {'source': 'daemon', 'source_epoch': 'session', 'scope': 's',
                'kind': 'node'}
        reduce(state, {**base, 'source_seq': 1,
                       'payload': {'node': '02', 'connected': False}})
        reduce(state, {**base, 'source_seq': 2,
                       'payload': {'node': '02', 'boot': 'b', 'connected': True}})
        reduce(state, {**base, 'source_seq': 3,
                       'payload': {'node': '02', 'connected': False}})
        reduce(state, {**base, 'source_seq': 4,
                       'payload': {'node': '02', 'boot': '0000000000000000',
                                   'connected': False}})
        self.assertEqual(state.nodes['s:02']['boot'], 'b')
        self.assertTrue(state.nodes['s:02']['connected'])

    def test_removed_new_boot_cannot_resurrect_retired_boot(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            base = {'source': 'daemon', 'source_epoch': 'session', 'scope': 's'}
            with Capture(path, 'id') as cap:
                for seq, boot, removed in [(1, 'old', False), (2, 'new', False),
                                           (3, 'new', True), (4, 'old', False)]:
                    cap.add({**base, 'source_seq': seq, 'kind': 'node',
                             'payload': {'node': '02', 'boot': boot, 'removed': removed}}, FakeClock())
                self.assertNotIn('s:02', cap.state.nodes)
            self.assertNotIn('s:02', replay(path).nodes)

    def test_route_hops_requires_fresh_coherent_evidence(self):
        state = State()
        base = {'source': 'daemon', 'scope': 's', 'kind': 'route'}
        for observer, hop, sampled in [('01', '02', 100), ('02', '03', 105)]:
            reduce(state, {**base, 'payload': {'observer': observer,
                                               'destination': '03', 'next_hop': hop,
                                               'valid': True, 'sample_mono_ns': sampled}})
        self.assertEqual(route_hops(state, 's', '01', '03', now_mono_ns=110,
                                    max_age_ns=20, max_skew_ns=10), 2)
        self.assertIsNone(route_hops(state, 's', '01', '03', now_mono_ns=130,
                                      max_age_ns=20, max_skew_ns=10))
        self.assertIsNone(route_hops(state, 's', '01', '03', now_mono_ns=110,
                                      max_age_ns=20, max_skew_ns=2))
        del state.routes['s:02:03']['sample_mono_ns']
        self.assertIsNone(route_hops(state, 's', '01', '03', now_mono_ns=110,
                                      max_age_ns=20, max_skew_ns=10))

    def test_capture_detaches_input_and_rejects_malformed_event_atomically(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            with Capture(path, 'id') as cap:
                event = {'source': 'daemon', 'scope': 's', 'kind': 'sample',
                         'payload': {'series': 'rssi', 'value': {'dbm': -40}}}
                cap.add(event, FakeClock())
                event['payload']['value']['dbm'] = -10
                self.assertEqual(cap.state.samples['s:rssi']['value']['dbm'], -40)
                with self.assertRaises(ValueError):
                    cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                             'payload': {'boot': 'a'}}, FakeClock())
                self.assertEqual(cap.seq, 1)
                self.assertFalse(cap.failed)
            self.assertEqual(replay(path).samples['s:rssi']['value']['dbm'], -40)

    def test_unclean_prefix_seek_has_no_future_gap(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            cap = Capture(path, 'id')
            cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                     'payload': {'node': '02'}}, FakeClock())
            cap.flush()
            cap.db.close()
            self.assertEqual(replay(path, until_seq=1).gaps, [])
            self.assertEqual(replay(path).gaps[-1]['reason'], 'UncleanEnd')

    def test_capture_path_with_uri_characters_and_sample_time_index(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'capture ?#1.rlcapture'
            clock = FakeClock(123_000_000, 456)
            with Capture(path, 'id') as cap:
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'sample',
                         'payload': {'series': 'rssi', 'value': -40}}, clock)
            with sqlite3.connect(path / 'data.sqlite') as db:
                columns = {row[1] for row in db.execute('PRAGMA table_info(metric_samples)')}
                self.assertIn('t_mono_ns', columns)
                self.assertEqual(db.execute('SELECT t_mono_ns FROM metric_samples').fetchone()[0], 123_000_000)
                indexes = {row[1] for row in db.execute('PRAGMA index_list(metric_samples)')}
                self.assertIn('metric_series_time', indexes)
            self.assertEqual(replay(path).samples['s:rssi']['value'], -40)

    def test_closed_capture_has_versioned_manifest_and_database_digest(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            with Capture(path, 'id') as cap:
                cap.add({'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '02'}}, FakeClock())
            manifest = json.loads((path / 'manifest.json').read_text())
            self.assertEqual(manifest['versions'], {})
            self.assertEqual(manifest['scopes'], [])
            checksums = json.loads((path / 'checksums.json').read_text())
            self.assertTrue(checksums['closed'])
            self.assertEqual(checksums['schema_version'], 1)
            self.assertEqual(checksums['files']['data.sqlite']['sha256'],
                             hashlib.sha256((path / 'data.sqlite').read_bytes()).hexdigest())

    def test_capture_rejects_sequence_outside_sqlite_integer_range(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            with Capture(path, 'id') as cap:
                with self.assertRaises(ValueError):
                    cap.add({'source': 'daemon', 'source_seq': 2**63, 'scope': 's',
                             'kind': 'node', 'payload': {'node': '02'}}, FakeClock())
                self.assertEqual(cap.seq, 0)
                self.assertFalse(cap.failed)

    def test_capture_rejects_monotonic_time_regression_before_insert(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            with Capture(path, 'id') as cap:
                event = {'source': 'daemon', 'scope': 's', 'kind': 'node',
                         'payload': {'node': '02'}}
                cap.add(event, FakeClock(100_000_000, 100))
                with self.assertRaises(ValueError):
                    cap.add(event, FakeClock(50_000_000, 50))
                self.assertEqual(cap.seq, 1)
            self.assertIn('s:02', replay(path).nodes)

    def test_capture_rejects_ambiguous_scoped_identifiers(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.rlcapture'
            with Capture(path, 'id') as cap:
                for scope, node in [('s:a', 'b'), ('s', 'a:b')]:
                    with self.assertRaises(ValueError):
                        cap.add({'source': 'daemon', 'scope': scope, 'kind': 'node',
                                 'payload': {'node': node}}, FakeClock())
                self.assertEqual(cap.seq, 0)

    def test_fake_api1_returns_invalid_request_for_bad_json_and_utf8(self):
        fake = FakeAPI1()
        for raw in (b'API1 {\n', b'API1 \xff\n', b'API1 []\n'):
            reply = json.loads(fake.feed(raw)[0])
            self.assertEqual(reply['v'], 1)
            self.assertFalse(reply['ok'])
            self.assertEqual(reply['error']['code'], 'INVALID_REQUEST')

    def test_fake_api1_response_matches_live_envelope_and_pagination(self):
        nodes = [{'node': f'{i:016x}'} for i in (1, 2, 3)]
        fake = FakeAPI1(nodes)
        def ask(request_id, method, params=None):
            request = {'v': 1, 'request_id': request_id, 'method': method,
                       'params': params or {}}
            return json.loads(fake.feed(b'API1 ' + json.dumps(request).encode() + b'\n')[0])
        capabilities = ask('c', 'capabilities.get')
        self.assertEqual(capabilities['v'], 1)
        self.assertTrue(capabilities['result']['methods']['nodes.list'])
        first = ask('n1', 'nodes.list', {'limit': 2})
        self.assertEqual([n['node'] for n in first['result']['nodes']],
                         ['0000000000000001', '0000000000000002'])
        self.assertEqual(first['result']['next_after'], '0000000000000002')
        second = ask('n2', 'nodes.list', {'after': first['result']['next_after']})
        self.assertEqual([n['node'] for n in second['result']['nodes']], ['0000000000000003'])
        self.assertIsNone(second['result']['next_after'])

    def test_fake_api1_fragmented_line_and_socket(self):
        server = FakeAPI1()
        self.assertEqual(server.feed(b'API1 {"v":1,"request_id":"a",')[0:1], [])
        replies = server.feed(b'"method":"capabilities.get","params":{}}\n')
        self.assertEqual(json.loads(replies[0])['request_id'], 'a')
        self.assertTrue(json.loads(replies[0])['result']['methods']['nodes.list'])
        fixture = Path(__file__).resolve().parents[1] / 'fixtures' / 'api1-nodes.json'
        with tempfile.TemporaryDirectory() as td, serve_fake_api1(Path(td) / 'api.sock'):
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(Path(td) / 'api.sock'))
                request = b'API1 ' + fixture.read_bytes()
                client.sendall(request[:7])
                client.sendall(request[7:])
                result = json.loads(client.recv(4096))
                self.assertEqual(result['request_id'], 'fixture-nodes')
                self.assertEqual(result['result']['nodes'], [])


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.a = Identity('esp32c3', '1', 'aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:01', '123', 4 * 1024 * 1024, False, False)
        self.b = Identity('esp32c3', '1', 'aa:bb:cc:dd:ee:02', 'aa:bb:cc:dd:ee:02', '124', 4 * 1024 * 1024, False, False)

    def test_reenumeration_requires_unique_identity(self):
        ports = [Port('COM1', None, None, None, 'hub-a', None), Port('COM2', None, None, None, 'hub-b', None)]
        self.assertIsNone(reconcile(self.a, ports, {}))
        self.assertEqual(reconcile(self.a, ports, {'COM2': self.a}), 'COM2')
        self.assertIsNone(reconcile(self.a, ports, {'COM1': self.a, 'COM2': self.a}))
        self.assertIsNone(reconcile(self.a, ports, {'COM2': self.b}))

    def test_preflight_no_write_and_partial_batch(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'app.bin'
            p.write_bytes(b'image')
            image = Image(0x10000, p, len(b'image'), hashlib.sha256(b'image').hexdigest())
            calls = []
            def worker(port, plan):
                # Probe and write belong to this one worker session.
                identity = self.a if port != 'COM2' else self.b
                plan.verify(port, identity)
                calls.append(port)
                if port == 'COM2':
                    raise OSError('unplugged')
            def plan(identity, **kw):
                return FlashPlan(identity, 'esp32c3', (image,), verified_signature=True, quiesced=True, **kw)
            cases = [plan(self.a, expected_mac=self.b.base_mac),
                     FlashPlan(self.a, 'esp32s3', (image,), True, self.a.base_mac, True),
                     plan(self.a, expected_mac=self.a.base_mac),
                     plan(self.b, expected_mac=self.b.base_mac)]
            rejected = [run_batch([(port, candidate)], worker)[0]
                        for port, candidate in zip(['COM0', 'COM0a'], cases[:2])]
            results = rejected + run_batch(list(zip(['COM1', 'COM2'], cases[2:])), worker)
            self.assertEqual([r.ok for r in results], [False, False, True, False])
            self.assertEqual(calls, ['COM1', 'COM2'])
            for corrupt in [Image(-1, p, 5, image.sha256), Image(0x10000, p, 5, '0'*64),
                            Image(0x10000, p, 6, image.sha256), Image(0x3fffff, p, 5, image.sha256)]:
                with self.assertRaises(ValueError):
                    FlashPlan(self.a, 'esp32c3', (corrupt,), True, self.a.base_mac, True).verify('COM1', self.a)
            with self.assertRaises(ValueError):
                FlashPlan(self.a, 'esp32c3', (image,), False, self.a.base_mac).verify('COM1', self.a)
            with self.assertRaises(ValueError):
                FlashPlan(self.a, 'esp32c3', (image, image), True, self.a.base_mac, True).verify('COM1', self.a)
            for identity in [Identity('esp32c3', '1', self.a.base_mac, self.a.sta_mac, '123', 4*1024*1024, None, False),
                             Identity('esp32c3', '1', self.a.base_mac, self.a.sta_mac, '123', 4*1024*1024, False, True)]:
                with self.assertRaises(ValueError):
                    plan(identity, expected_mac=identity.base_mac).verify('COM1', identity)
            self.assertEqual(calls, ['COM1', 'COM2'])

    def test_batch_rejects_duplicate_identity_before_writing(self):
        with tempfile.TemporaryDirectory() as td:
            image_path = Path(td) / 'app.bin'
            image_path.write_bytes(b'image')
            image = Image(0x10000, image_path, 5, hashlib.sha256(b'image').hexdigest())
            plan = FlashPlan(self.a, self.a.chip, (image,), True, self.a.base_mac, True)
            calls = []
            results = run_batch([('COM1', plan), ('COM2', plan)],
                                lambda port, _: calls.append(port))
            self.assertEqual([r.ok for r in results], [False, False])
            self.assertEqual(calls, [])

    def test_batch_continues_after_worker_runtime_failure(self):
        plans = [(port, FlashPlan(identity, identity.chip, (), False, identity.base_mac))
                 for port, identity in [('COM1', self.a), ('COM2', self.b)]]
        calls = []
        def worker(port, plan):
            calls.append(port)
            if port == 'COM1':
                raise RuntimeError('verification failed')
        results = run_batch(plans, worker)
        self.assertEqual([result.ok for result in results], [False, True])
        self.assertEqual(calls, ['COM1', 'COM2'])

    def test_batch_does_not_report_false_worker_result_as_success(self):
        plans = [(port, FlashPlan(identity, identity.chip, (), False, identity.base_mac))
                 for port, identity in [('COM1', self.a), ('COM2', self.b)]]
        results = run_batch(plans, lambda port, plan: port != 'COM1')
        self.assertEqual([result.ok for result in results], [False, True])

    def test_batch_continues_when_one_port_disappears(self):
        plans = [(port, FlashPlan(identity, identity.chip, (), False, identity.base_mac))
                 for port, identity in [(None, self.a), ('COM2', self.b)]]
        calls = []
        results = run_batch(plans, lambda port, plan: calls.append(port))
        self.assertEqual([result.ok for result in results], [False, True])
        self.assertEqual(calls, ['COM2'])

    def test_port_lease_blocks_different_board_on_same_port(self):
        first, second = PortLeases(), PortLeases()
        with first.acquire('board-a', 'COM1'):
            with self.assertRaises(ValueError):
                with second.acquire('board-b', 'COM1'):
                    pass
        with second.acquire('board-b', 'COM1'):
            pass

    def test_port_lease_blocks_alias_of_same_device(self):
        with tempfile.TemporaryDirectory() as td:
            actual = Path(td) / 'ttyUSB0'
            alias = Path(td) / 'by-id'
            actual.touch()
            alias.symlink_to(actual)
            first, second = PortLeases(), PortLeases()
            with first.acquire('board-a', str(actual)):
                with self.assertRaises(ValueError):
                    with second.acquire('board-b', str(alias)):
                        pass

    def test_rom_attaches_flash_and_pins_verified_image(self):
        class ROM:
            CHIP_NAME = 'ESP32-C3'
            def __init__(self):
                self._port = self
                self.attached = False
            def close(self):
                pass
            def read_mac(self, kind):
                return bytes.fromhex('aabbccddee01')
            def flash_id(self):
                if not self.attached:
                    raise RuntimeError('flash not attached')
                return 0x164020
            def get_chip_revision(self):
                return 1
            def get_security_info(self, cache=False):
                return {'parsed_flags': {'SECURE_BOOT_EN': False}, 'flash_crypt_cnt': 0}
        class API:
            __version__ = '5.4.0'
            def __init__(self):
                self.rom = ROM()
                self.written = None
            def detect_chip(self, **kw):
                return self.rom
            def attach_flash(self, esp):
                esp.attached = True
            def write_flash(self, esp, images, **kw):
                self.written = images
                image_path.write_bytes(b'other')
            def verify_flash(self, esp, images):
                self.assert_images = images
        with tempfile.TemporaryDirectory() as td:
            image_path = Path(td) / 'app.bin'
            image_path.write_bytes(b'image')
            image = Image(0x10000, image_path, 5, hashlib.sha256(b'image').hexdigest())
            expected = Identity('esp32c3', '1', self.a.base_mac, None,
                                '164020', 4 * 1024 * 1024, False, False)
            api = API()
            with patch('routeloom_meshviz.flash_worker.verify_bundle', return_value={
                    'chip': 'esp32c3', 'files': [{'offset': image.offset, 'path': 'app.bin',
                                                 'size': image.size, 'sha256': image.sha256}]}):
                flash('COM1', FlashPlan(expected, 'esp32c3', (image,), True,
                                       self.a.base_mac, True, Path(td)), api)
            self.assertEqual(api.written, [(0x10000, b'image')])
            self.assertEqual(api.assert_images, api.written)

    def test_rom_worker_rejects_before_write(self):
        class ROM:
            CHIP_NAME = 'ESP32-C3'
            def __init__(self):
                self._port = self
            def close(self):
                pass
            def read_mac(self, kind):
                return bytes.fromhex('aabbccddee01')
            def flash_id(self):
                return 0x401620
            def get_chip_revision(self):
                return 1
            def get_security_info(self, cache=False):
                return {'parsed_flags': {'SECURE_BOOT_EN': False}, 'flash_crypt_cnt': 0}
        class API:
            __version__ = '5.4.0'
            def __init__(self):
                self.calls = 0
            def detect_chip(self, **kw):
                return ROM()
            def attach_flash(self, esp):
                pass
            def write_flash(self, *args, **kw):
                self.calls += 1
            def verify_flash(self, *args, **kw):
                pass
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'app.bin'
            p.write_bytes(b'image')
            image = Image(0x10000, p, 5, hashlib.sha256(b'image').hexdigest())
            api = API()
            # ROM measurement differs in flash ID and flash capacity: fail closed.
            with self.assertRaises(ValueError):
                flash('COM1', FlashPlan(self.a, 'esp32c3', (image,), True, self.a.base_mac, True), api)
            self.assertEqual(api.calls, 0)

    def test_rom_same_session_and_unknown_security_fail_closed(self):
        class ROM:
            CHIP_NAME = 'ESP32-C3'
            def __init__(self, secure):
                self._port = self
                self.secure = secure
                self.closed = False
            def close(self):
                self.closed = True
            def read_mac(self, kind):
                return bytes.fromhex('aabbccddee01')
            def flash_id(self):
                return 0x164020
            def get_chip_revision(self):
                return 1
            def get_security_info(self, cache=False):
                return {'parsed_flags': {'SECURE_BOOT_EN': self.secure}, 'flash_crypt_cnt': 0}
        class API:
            __version__ = '5.4.0'
            def __init__(self, secure):
                self.rom = ROM(secure)
                self.writes = []
            def detect_chip(self, **kw):
                return self.rom
            def attach_flash(self, esp):
                pass
            def write_flash(self, esp, images, **kw):
                self.writes.append(esp)
            def verify_flash(self, esp, images):
                self.writes.append(esp)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'app.bin'
            p.write_bytes(b'image')
            image = Image(0x10000, p, 5, hashlib.sha256(b'image').hexdigest())
            expected = Identity('esp32c3', '1', self.a.base_mac, None,
                                '164020', 4 * 1024 * 1024, False, False)
            plan = FlashPlan(expected, 'esp32c3', (image,), True, self.a.base_mac, True,
                             Path(td))
            verifier = patch('routeloom_meshviz.flash_worker.verify_bundle', return_value={
                'chip': 'esp32c3', 'files': [{'offset': image.offset, 'path': 'app.bin',
                                             'size': image.size, 'sha256': image.sha256}]})
            verifier.start()
            self.addCleanup(verifier.stop)
            api = API(False)
            flash('COM1', plan, api)
            self.assertEqual(api.writes, [api.rom, api.rom])
            self.assertTrue(api.rom.closed)
            api = API(False)
            with patch.dict(sys.modules, {'esptool': api}):
                flash('COM1', plan)
            self.assertEqual(api.writes, [api.rom, api.rom])
            api = API(False)
            claimed_sta = Identity('esp32c3', '1', self.a.base_mac, self.a.base_mac,
                                   '164020', 4 * 1024 * 1024, False, False)
            with self.assertRaises(ValueError):
                flash('COM1', FlashPlan(claimed_sta, 'esp32c3', (image,), True,
                                       self.a.base_mac, True, Path(td)), api)
            self.assertEqual(api.writes, [])
            api = API(None)
            with self.assertRaises(ValueError):
                flash('COM1', plan, api)
            self.assertEqual(api.writes, [])
            api = API(False)
            api.rom.get_security_info = lambda cache=False: {'parsed_flags': {}}
            with self.assertRaises(ValueError):
                flash('COM1', plan, api)
            self.assertEqual(api.writes, [])

    def test_default_plan_is_not_authorized(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'app.bin'
            p.write_bytes(b'image')
            with self.assertRaises(ValueError):
                FlashPlan(self.a, 'esp32c3', (Image(0x10000, p, 5, hashlib.sha256(b'image').hexdigest()),),
                          True, self.a.base_mac).verify('COM1', self.a)

    def test_json_worker_rejects_client_signature_claim(self):
        request = {'port': 'COM1', 'expected': self.a.__dict__, 'chip': 'esp32c3',
                   'images': [], 'expected_mac': self.a.base_mac,
                   'verified_signature': True}
        result = subprocess.run(
            [sys.executable, '-m', 'routeloom_meshviz.flash_worker'],
            input=json.dumps(request), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)['ok'])

    def test_lease_recovers_after_directory_error(self):
        with tempfile.TemporaryDirectory() as td:
            leases = PortLeases()
            leases.directory = Path(td) / 'blocked'
            leases.directory.write_text('not a directory', encoding='utf-8')
            with self.assertRaises(OSError):
                with leases.acquire('board-a'):
                    pass
            self.assertEqual(leases.held, set())
            leases.directory.unlink()
            with leases.acquire('board-a'):
                self.assertEqual(leases.held, {'board-a'})

    def test_lease_and_rig_import(self):
        with PortLeases() as leases:
            with leases.acquire('board-a'):
                with self.assertRaises(ValueError):
                    with leases.acquire('board-a'):
                        pass
        rigs = import_rig(Path(__file__).resolve().parents[2] / 'hil' / 'rigs.yaml')
        self.assertIn('bridge', rigs['bench-2026-09-26'].boards)

    def test_rig_import_never_executes_code_beside_selected_file(self):
        with tempfile.TemporaryDirectory() as td:
            rig_path = Path(td) / 'rigs.yaml'
            marker = Path(td) / 'executed'
            rig_path.write_text('{}', encoding='utf-8')
            (Path(td) / 'rig.py').write_text(
                f'from pathlib import Path\nPath({str(marker)!r}).write_text("yes")\n'
                'def load_rigs(path):\n    return {}\n', encoding='utf-8')
            result = subprocess.run(
                [sys.executable, '-c',
                 'from routeloom_meshviz.device import import_rig; '
                 'import sys; import_rig(sys.argv[1])', str(rig_path)],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
