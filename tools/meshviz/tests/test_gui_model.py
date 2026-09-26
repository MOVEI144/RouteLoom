"""Qt-free GUI support: model→display conversion, API1 normalization, trials, board plans, export."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from routeloom_meshviz import views
from routeloom_meshviz.api1_adapter import LineDecoder, NodesNormalizer, encode_request
from routeloom_meshviz.board_setup import BoardRow, assignment_errors, normalize_node_id, preview
from routeloom_meshviz.capture import Capture
from routeloom_meshviz.demo import GATEWAY, DemoMesh, write_demo_capture
from routeloom_meshviz.device import Identity
from routeloom_meshviz.fake_api1 import FakeAPI1
from routeloom_meshviz.model import FakeClock, State, reduce
from routeloom_meshviz.playback import CaptureReader, export_capture, read_trial_csv
from routeloom_meshviz.trial import (TrialPlan, TrialRunner, nearest_rank, summarize, validate)


def node(n, **fields):
    base = {'node': f'{n:016x}', 'role': 'peer', 'connected': True, 'listed': True,
            'neighbor': False, 'direct': False, 'hops': None, 'next_hop': None,
            'route_metric': None, 'link_cost': None, 'rssi_dbm': None, 'rssi_avg_dbm': None,
            'telemetry_stale': None, 'last_heard_ms': 1000, 'heard_age_ms': 5,
            'updated_ms': 1000, 'changed_ms': 0}
    return {**base, **fields}


def gateway_view():
    return [node(1, role='gateway', hops=0, telemetry_stale=False),
            node(2, neighbor=True, direct=True, hops=1, next_hop=f'{2:016x}', rssi_dbm=-51,
                 link_cost=1, route_metric=10),
            node(3, next_hop=f'{2:016x}', route_metric=20),
            node(4, connected=False),
            node(5, connected=False, listed=False)]


class Api1AdapterTests(unittest.TestCase):
    def test_codec_frames_and_bounds(self):
        line = encode_request('r1', 'nodes.list', {'limit': 1})
        self.assertTrue(line.startswith(b'API1 ') and line.endswith(b'\n'))
        decoder = LineDecoder()
        self.assertEqual(decoder.feed(b'{"v":1,"request_id":"a"'), [])
        self.assertEqual(decoder.feed(b',"ok":true,"result":{}}\n')[0]['request_id'], 'a')
        with self.assertRaises(ValueError):
            decoder.feed(b'x' * 70000)
        with self.assertRaises(ValueError):
            encode_request('r', 'm', {'p': 'x' * 9000})
        with self.assertRaises(ValueError):
            LineDecoder().feed(b'{"v":1,"request_id":[],"ok":true,"result":{}}\n')
        with self.assertRaises(ValueError):
            LineDecoder().feed(b'{"v":1,"request_id":"r","ok":true,"result":{"x":NaN}}\n')

    def test_gateway_view_keeps_unknown_and_no_route_distinct(self):
        normalizer = NodesNormalizer(1)
        events = normalizer.events({'gateway': f'{1:016x}', 'session_id': 7, 'state': 'live'},
                                   gateway_view(), 2000)
        state = State()
        for event in events:
            reduce(state, event)
        model = views.topology(state)
        self.assertEqual(model.gateway, f'{1:016x}')
        # Multi-hop hop counts stay unknown: route metric is never converted into hops.
        self.assertIsNone(model.nodes[f'{3:016x}']['hops'])
        self.assertEqual(views.fmt(model.nodes[f'{3:016x}']['hops']), '不明')
        self.assertEqual(model.nodes[f'{2:016x}']['hops'], 1)
        # Only the direct neighbor is a physical edge; 3 is reached "via 2", not a proven link.
        self.assertEqual(set(model.phys_edges), {(f'{1:016x}', f'{2:016x}')})
        self.assertFalse(model.phys_edges[(f'{1:016x}', f'{2:016x}')]['bidirectional'])
        self.assertEqual(model.route_edges[f'{3:016x}'], f'{2:016x}')
        # Listed but unreachable = observed "no route"; departed node has no route claim.
        self.assertIn(f'{4:016x}', model.no_route)
        self.assertNotIn(f'{5:016x}', model.no_route)
        self.assertEqual([model.nodes[f'{n:016x}']['state'] for n in (2, 4, 5)],
                         ['接続', '通信なし', '消滅'])
        self.assertEqual(model.tree_edges, {})
        rows = {r['node']: r for r in views.quality_rows(state, model.scope, 2000)}
        self.assertEqual(rows[f'{3:016x}']['rssi'], '不明')
        self.assertEqual(rows[f'{2:016x}']['rssi'], '-51 dBm')
        self.assertEqual(rows[f'{2:016x}']['heap'], '未取得')
        self.assertEqual(rows[f'{2:016x}']['observed'], '1.0 s')

    def test_unchanged_poll_emits_nothing_and_session_change_retires_claims(self):
        normalizer = NodesNormalizer(1)
        source = {'gateway': f'{1:016x}', 'session_id': 1}
        first = normalizer.events(source, gateway_view(), 2000)
        self.assertEqual([e['kind'] for e in first], ['snapshot', 'sample'])
        # heard_age_ms changes every poll without a new observation behind it.
        again = [dict(n, heard_age_ms=n['heard_age_ms'] + 2000) for n in gateway_view()]
        self.assertEqual(normalizer.events(source, again, 4000), [])
        state = State()
        for event in first:
            reduce(state, event)
        lost = normalizer.events({'gateway': f'{1:016x}', 'session_id': None}, [], 6000)
        self.assertNotEqual(lost[0]['source_epoch'], first[0]['source_epoch'])
        for event in lost:
            reduce(state, event)
        self.assertEqual(state.nodes, {})

    def test_gateway_change_retires_previous_claims_even_with_same_session_number(self):
        normalizer = NodesNormalizer(1)
        state = State()
        for event in normalizer.events({'gateway': f'{1:016x}', 'session_id': 1},
                                       gateway_view(), 2000):
            reduce(state, event)
        for event in normalizer.events({'gateway': f'{9:016x}', 'session_id': 1},
                                       [node(9, role='gateway', hops=0)], 4000):
            reduce(state, event)
        self.assertEqual(set(state.nodes), {f'gw-{9:016x}:{9:016x}'})


class DemoAndFakeServerTests(unittest.TestCase):
    def mesh(self, count=8):
        self.clock = FakeClock(0, 1_790_000_000_000)
        return DemoMesh(count, clock=lambda: (self.clock.mono_ns // 1_000_000, self.clock.unix_ms))

    def test_relay_failure_switches_routes_and_last_node_departs(self):
        mesh = self.mesh()
        before = {n['node']: n for n in mesh.gateway_nodes()}
        self.assertEqual(before[f'{5:016x}']['next_hop'], f'{2:016x}')
        self.clock.advance(20_000)
        during = {n['node']: n for n in mesh.gateway_nodes()}
        self.assertFalse(during[f'{2:016x}']['connected'])
        # Orphans re-attach to the nearest live ancestor: gateway-direct now.
        self.assertEqual(during[f'{5:016x}']['next_hop'], f'{5:016x}')
        self.clock.advance(12_000)
        after = {n['node']: n for n in mesh.gateway_nodes()}
        self.assertFalse(after[f'{8:016x}']['listed'])

    def test_fake_server_send_subset_enforces_admission(self):
        mesh = self.mesh()
        fake = FakeAPI1(mesh=mesh)

        def ask(method, params):
            line = encode_request('r', method, params)
            return json.loads(fake.feed(line)[0])

        self.assertTrue(ask('capabilities.get', {})['result']['methods']['messages.submit'])
        epoch = ask('operations.open_epoch', {'network': '0' * 15 + '1'})['result']['admission_epoch']
        submit = {'network': '0' * 15 + '1', 'admission_epoch': epoch, 'key': 'a' * 32,
                  'destination': {'kind': 'node', 'id': f'{3:016x}'}, 'payload_hex': '00',
                  'payload_len': 1}
        op = ask('messages.submit', submit)['result']['operation_id']
        self.assertEqual(ask('messages.submit', submit)['result']['operation_id'], op)
        conflict = ask('messages.submit', {**submit, 'payload_hex': '01'})
        self.assertEqual(conflict['error']['code'], 'CONFLICT')
        for i in range(13):
            ask('messages.submit', {**submit, 'key': f'{i:032x}'})
        limited = ask('messages.submit', {**submit, 'key': 'b' * 32})
        self.assertEqual(limited['error']['code'], 'RATE_LIMITED')
        self.assertGreater(limited['error']['detail']['retry_after_ms'], 0)
        self.clock.advance(1000)
        self.assertEqual(ask('operations.get', {'operation_id': op})['result']['dispatch_state'],
                         'END_SDK_RECEIVED')


class TrialTests(unittest.TestCase):
    def plan(self, **fields):
        return TrialPlan(**{'network': '0' * 15 + '1', 'destination': f'{3:016x}', 'count': 3,
                            'interval_ms': 1000, 'payload_len': 16, **fields})

    def test_plan_respects_admission_budget(self):
        self.assertEqual(validate(self.plan()), [])
        errors = validate(self.plan(count=20, interval_ms=5000))
        self.assertTrue(any('admission' in e for e in errors))
        self.assertEqual(validate(self.plan(count=20, interval_ms=30_000)), [])
        self.assertTrue(validate(self.plan(payload_len=129, destination='xyz')))
        # design-devflow.md §5.2: the host command bound is the 96 B HostOps
        # lane, not the 128 B unicast ceiling.
        self.assertEqual(validate(self.plan(payload_len=96)), [])
        self.assertTrue(validate(self.plan(payload_len=97)))
        self.assertTrue(validate(self.plan(network='0000000100000000')))
        self.assertTrue(validate(self.plan(network='0000000000000000')))
        self.assertTrue(validate(self.plan(destination='ffffffffffffffff')))
        self.assertTrue(validate(self.plan(destination='0000000000000000')))

    def test_runner_against_fake_server_and_unknowns(self):
        clock = FakeClock(0, 1_790_000_000_000)
        mesh = DemoMesh(8, clock=lambda: (clock.mono_ns // 1_000_000, clock.unix_ms))
        fake = FakeAPI1(mesh=mesh)
        runner = TrialRunner(self.plan(count=4), 0)
        dropped = False
        for _ in range(200):
            now = clock.mono_ns // 1_000_000
            for tag, method, params in runner.due(now):
                if method == 'messages.submit' and params['key'] == runner.messages[2]['key'] and not dropped:
                    dropped = True  # the reply is lost in transport
                    continue
                reply = json.loads(fake.feed(encode_request(tag, method, params))[0])
                runner.on_reply(tag, reply, now)
            if runner.finished:
                break
            clock.advance(250)
        self.assertEqual(runner.state, 'Completed')
        summary = runner.summary()
        self.assertEqual(summary['submitted'], 4)
        self.assertEqual(summary['admitted'], 3)
        self.assertEqual(summary['success'], 3)
        # The lost admission reply stays unknown; it is not resubmitted with a new key.
        self.assertEqual(runner.messages[2]['result'], 'unknown')
        self.assertEqual(summary['unknown'], 1)
        self.assertEqual(summary['refused'], {})
        self.assertEqual(summary['success_rate_min'], 1.0)
        planned = [m['planned_ms'] for m in runner.messages]
        self.assertEqual([b - a for a, b in zip(planned, planned[1:])], [1000, 1000, 1000])

    def test_lost_submit_reply_uses_key_lookup_without_resending(self):
        clock = FakeClock(0, 1_790_000_000_000)
        mesh = DemoMesh(8, clock=lambda: (clock.mono_ns // 1_000_000, clock.unix_ms))
        fake = FakeAPI1(mesh=mesh)
        runner = TrialRunner(self.plan(count=1), 0, reconcile=True)
        submits = 0
        lookups = 0
        for _ in range(180):
            now = clock.mono_ns // 1_000_000
            for tag, method, params in runner.due(now):
                reply = json.loads(fake.feed(encode_request(tag, method, params))[0])
                if method == 'messages.submit':
                    submits += 1
                    runner.on_reply(tag, None, now)
                else:
                    lookups += method == 'operations.get_by_key'
                    runner.on_reply(tag, reply, now)
            if runner.finished:
                break
            clock.advance(250)
        self.assertEqual((submits, lookups), (1, 1))
        self.assertEqual(runner.messages[0]['result'], 'END_SDK_RECEIVED')
        self.assertIsNone(runner.messages[0]['admitted_ms'])
        self.assertEqual(runner.summary()['success'], 1)

    def test_rate_limited_submit_is_refused_and_shifts_schedule(self):
        runner = TrialRunner(self.plan(count=2), 0)
        (tag, _, _), = runner.due(0)
        runner.on_reply(tag, {'v': 1, 'ok': True, 'result': {'admission_epoch': '0' * 16}}, 0)
        (tag, method, _), = runner.due(0)
        self.assertEqual(method, 'messages.submit')
        runner.on_reply(tag, {'v': 1, 'ok': False, 'error': {
            'code': 'RATE_LIMITED', 'detail': {'retry_after_ms': 30_000}}}, 0)
        self.assertEqual(runner.messages[0]['result'], 'refused')
        self.assertEqual(runner.due(1000), [])
        self.assertEqual(runner.due(31_000)[0][1], 'messages.submit')
        self.assertEqual(summarize(runner.messages)['refused'], {'RATE_LIMITED': 1})

    def test_rate_limited_epoch_waits_before_retrying(self):
        runner = TrialRunner(self.plan(count=1), 0)
        (tag, _, _), = runner.due(0)
        runner.on_reply(tag, {'ok': False, 'error': {'code': 'RATE_LIMITED',
                        'detail': {'retry_after_ms': 30_000}}}, 0)
        self.assertEqual(runner.due(250), [])
        self.assertEqual(runner.due(29_999), [])
        self.assertEqual(runner.due(30_000)[0][1], 'operations.open_epoch')

    def test_malformed_epoch_reply_does_not_crash_runner(self):
        runner = TrialRunner(self.plan(count=1), 0)
        (tag, _, _), = runner.due(0)
        runner.on_reply(tag, {'ok': True, 'result': {}}, 0)
        self.assertEqual(runner.state, 'Aborted')

    def test_abort_stops_new_sends(self):
        runner = TrialRunner(self.plan(count=5), 0)
        (tag, _, _), = runner.due(0)
        runner.on_reply(tag, {'v': 1, 'ok': True, 'result': {'admission_epoch': '0' * 16}}, 0)
        runner.abort()
        self.assertEqual(runner.state, 'Aborted')
        self.assertEqual(runner.due(10_000), [])
        self.assertEqual({m['result'] for m in runner.messages}, {'not_sent'})

    def test_closing_source_leaves_unsettled_messages_unknown(self):
        runner = TrialRunner(self.plan(count=3), 0)
        (tag, _, _), = runner.due(0)
        runner.on_reply(tag, {'v': 1, 'ok': True, 'result': {'admission_epoch': '0' * 16}}, 0)
        (tag, _, _), = runner.due(0)
        runner.on_reply(tag, {'v': 1, 'ok': True, 'result': {'operation_id': 'o', 'dispatch_state':
                                                               'HOST_QUEUED'}}, 5)
        runner.abort('closed', drain=False)
        self.assertTrue(runner.finished)
        self.assertEqual([m['result'] for m in runner.messages], ['unknown', 'not_sent', 'not_sent'])
        self.assertIsNone(runner.messages[0]['terminal_ms'])
        self.assertEqual(runner.summary()['success_rate_max'], 1.0)
        self.assertEqual(runner.summary()['success_rate_min'], 0.0)

    def test_nearest_rank(self):
        self.assertIsNone(nearest_rank([], .5))
        values = list(range(1, 101))
        self.assertEqual([nearest_rank(values, q) for q in (.5, .9, .95, .99)], [50, 90, 95, 99])
        self.assertEqual(nearest_rank([7, 3], .5), 3)


class BoardSetupTests(unittest.TestCase):
    def identity(self, mac='aa:bb:cc:00:00:01', chip='esp32c3', secure=False, crypt=False):
        return Identity(chip, '4', mac, None, '164020', 4 << 20, secure, crypt)

    def manifest(self, **fields):
        return {'chip': 'esp32c3', 'role': 'reference_node', 'chip_revision_range': [0, 99],
                'minimum_flash_bytes': 2 << 20, 'firmware_version': 't', 'bundle_id': 'b',
                'security_profile': 'dev_ram',
                'files': [{'offset': 0x10000, 'path': 'images/application.bin', 'size': 4,
                           'sha256': '0' * 64}], **fields}

    def test_duplicate_node_id_and_board_are_rejected(self):
        rows = [BoardRow('A', identity=self.identity(), role='reference_node', node_id='2'),
                BoardRow('B', identity=self.identity('aa:bb:cc:00:00:02'), role='reference_node',
                         node_id='0x0002'),
                BoardRow('C', identity=self.identity(), role='bridge_node', node_id='3')]
        errors = assignment_errors(rows)
        self.assertTrue(any('NodeId' in e for e in errors['A']))
        self.assertTrue(any('NodeId' in e for e in errors['B']))
        self.assertTrue(any('MAC' in e for e in errors['C']))
        self.assertEqual(normalize_node_id('0x0002'), f'{2:016x}')
        self.assertIsNone(normalize_node_id('0'))
        self.assertIsNone(normalize_node_id('ffffffffffffffff'))
        self.assertIsNone(normalize_node_id('xyz'))

    def test_preview_lists_every_safety_reason_and_builds_plan_only_when_clear(self):
        row = BoardRow('A', identity=self.identity(chip='esp32s3', crypt=None), role='bridge_node',
                       node_id='2')
        plan, reasons, _ = preview(row, self.manifest(), Path('/b'), quiesced=False)
        self.assertIsNone(plan)
        text = '\n'.join(reasons)
        for expected in ('chip 不一致', '役割', 'quiesce', '暗号化'):
            self.assertIn(expected, text)
        row = BoardRow('A', identity=self.identity(), role='reference_node', node_id='2')
        plan, reasons, notes = preview(row, self.manifest(), Path('/b'), quiesced=True,
                                       image_node_id=f'{2:016x}')
        self.assertEqual(reasons, [])
        self.assertEqual(plan.expected_mac, row.identity.base_mac)
        self.assertTrue(any('個体別設定' in note for note in notes))
        plan, reasons, _ = preview(row, self.manifest(chip='esp32c6'), Path('/b'), quiesced=True)
        self.assertTrue(any('C6' in r for r in reasons))

    def test_preview_rejects_node_id_not_embedded_in_signed_image(self):
        row = BoardRow('A', identity=self.identity(), role='reference_node', node_id='2')
        plan, reasons, _ = preview(row, self.manifest(), Path('/b'), quiesced=True,
                                   image_node_id='0000000000000001')
        self.assertIsNone(plan)
        self.assertTrue(any('NodeId' in reason for reason in reasons))


class ProbeTests(unittest.TestCase):
    def test_probe_is_read_only_and_reports_unknown_protection(self):
        from routeloom_meshviz.flash_worker import probe
        calls = []

        class ROM:
            CHIP_NAME = 'ESP32-S3'
            _port = type('P', (), {'close': lambda self: calls.append('close')})()
            def read_mac(self, kind): return bytes.fromhex('aabbccddee02')
            def flash_id(self): return 0x174020
            def get_chip_revision(self): return 1
            def get_security_info(self, cache=False): return {'parsed_flags': {}, 'flash_crypt_cnt': None}

        class API:
            __version__ = '5.4.0'
            def detect_chip(**kw): return ROM()
            def attach_flash(esp): calls.append('attach')
            def write_flash(*a, **kw): calls.append('write')
            def verify_flash(*a, **kw): calls.append('verify')

        identity = probe('COM9', API)
        self.assertEqual((identity.chip, identity.base_mac, identity.flash_bytes),
                         ('esp32s3', 'aa:bb:cc:dd:ee:02', 8 << 20))
        self.assertIsNone(identity.secure_boot)
        self.assertIsNone(identity.flash_encryption)
        self.assertEqual(calls, ['attach', 'close'])


class CaptureExportTests(unittest.TestCase):
    def test_demo_capture_tree_hops_seek_and_export_match_summary(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'demo.rlcapture'
            write_demo_capture(path, count=10, duration_s=30)
            reader = CaptureReader(path)
            try:
                seq = reader.index[0][0]
                state = reader.state_at(seq)
                model = views.topology(state, now_mono_ns=reader.index[0][1])
                self.assertEqual(model.gateway, GATEWAY)
                self.assertEqual(model.tree_edges[f'{5:016x}'], f'{2:016x}')
                # Derived hops come from a fresh, coherent node→gateway chain.
                self.assertEqual(model.nodes[f'{5:016x}']['hops'], 2)
                self.assertEqual(views.path_to_gateway(model, f'{8:016x}'),
                                 [f'{8:016x}', f'{3:016x}', GATEWAY])
                # A stale chain is unknown, not a hop count.
                stale = views.topology(state, now_mono_ns=reader.index[0][1] + 10**12)
                self.assertIsNone(stale.nodes[f'{5:016x}']['hops'])
                later = reader.seq_at(reader.index[0][1] + 20_000_000_000)
                self.assertFalse(views.topology(reader.state_at(later)).nodes[f'{2:016x}']['state'] == '接続')
                self.assertTrue(reader.series(later))
            finally:
                reader.close()

    def test_export_csv_reaggregates_to_same_trial_summary(self):
        with tempfile.TemporaryDirectory() as td:
            clock = FakeClock(1, 1_790_000_000_000)
            messages = [
                {'run_id': 'r', 'index': 0, 'key': 'k0', 'destination': f'{3:016x}', 'payload_len': 8,
                 'planned_ms': 0, 'submit_ms': 0, 'admitted_ms': 5, 'terminal_ms': 900,
                 'operation_id': 'o0', 'admission': 'ACCEPTED', 'dispatch_state': 'END_SDK_RECEIVED',
                 'result': 'END_SDK_RECEIVED'},
                {'run_id': 'r', 'index': 1, 'key': 'k1', 'destination': f'{3:016x}', 'payload_len': 8,
                 'planned_ms': 1000, 'submit_ms': 1000, 'admitted_ms': 1004, 'terminal_ms': 40_000,
                 'operation_id': 'o1', 'admission': 'ACCEPTED', 'dispatch_state': 'GATEWAY_ACCEPTED',
                 'result': 'unknown'},
                {'run_id': 'r', 'index': 2, 'key': 'k2', 'destination': f'{3:016x}', 'payload_len': 8,
                 'planned_ms': 2000, 'submit_ms': 2000, 'admitted_ms': None, 'terminal_ms': 2000,
                 'operation_id': None, 'admission': 'RATE_LIMITED', 'dispatch_state': None,
                 'result': 'refused'}]
            path = Path(td) / 'c.rlcapture'
            with Capture(path, 'c') as capture:
                capture.add({'kind': 'trial_run', 'source': 'meshviz-trial',
                             'payload': {'run_id': 'r', 'plan': None, 'state': 'Completed',
                                         'stop_reason': None}}, clock)
                for message in messages:
                    capture.add({'kind': 'trial_message', 'source': 'meshviz-trial',
                                 'payload': {**message, 'result': 'planned'}}, clock)
                    capture.add({'kind': 'trial_message', 'source': 'meshviz-trial',
                                 'payload': message}, clock)
                capture.add({'kind': 'snapshot', 'scope': 's', 'source': 'api1',
                             'payload': {'complete': True, 'nodes': [node(3, rssi_dbm=None)]}}, clock)
            out = export_capture(path, Path(td) / 'out')
            expected = summarize(messages)
            exported = json.loads((out / 'trial_summary.json').read_text())['r']
            recomputed = summarize(read_trial_csv(out / 'trial_messages.csv'))
            for key in ('submitted', 'admitted', 'success', 'unknown', 'refused', 'latency_ms',
                        'success_rate_min', 'success_rate_max'):
                self.assertEqual(exported[key], expected[key], key)
                self.assertEqual(recomputed[key], expected[key], key)
            with (out / 'nodes.csv').open(encoding='utf-8') as stream:
                row = next(csv.DictReader(stream))
            # Nullable values stay empty in CSV instead of becoming 0; IDs keep 16 hex digits.
            self.assertEqual(row['rssi_dbm'], '')
            self.assertEqual(row['node'], f'{3:016x}')
            self.assertEqual(len((out / 'events.jsonl').read_text().splitlines()), 8)


class FormatTests(unittest.TestCase):
    def test_unknown_is_never_zero(self):
        self.assertEqual(views.fmt(None), '不明')
        self.assertEqual(views.fmt(0, 'dBm'), '0 dBm')
        self.assertEqual(views.fmt_rate(None), '不明')
        self.assertEqual(views.fmt_age(None, 5), '不明')
        self.assertEqual(views.freshness(40_000, 1_000), '古い')
        self.assertEqual(views.participation({'connected': None}), '不明')
        self.assertEqual(views.short_id(f'{2:016x}'), '02')


if __name__ == '__main__':
    unittest.main()
