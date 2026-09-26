import hashlib
import json
import socket
import tempfile
import unittest
from pathlib import Path

from routeloom_meshviz.model import FakeClock, State, reduce, route_hops
from routeloom_meshviz.capture import Capture, replay
from routeloom_meshviz.fake_api1 import FakeAPI1, serve_fake_api1
from routeloom_meshviz.device import (Identity, Port, reconcile, PortLeases,
                                     Image, FlashPlan, run_batch, import_rig)
from routeloom_meshviz.flash_worker import flash


class ModelTests(unittest.TestCase):
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

    def test_fake_api1_fragmented_and_reordered(self):
        server = FakeAPI1()
        self.assertEqual(server.feed(b'API1 {"v":1,"request_id":"a",')[0:1], [])
        replies = server.feed(b'"method":"capabilities.get","params":{}}\n')
        self.assertEqual(json.loads(replies[0])['request_id'], 'a')
        self.assertEqual(json.loads(replies[0])['result']['methods'], ['nodes.list'])
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
            def write(port, identity, images):
                calls.append(port)
                if port == 'COM2':
                    raise OSError('unplugged')
            def plan(identity, **kw):
                return FlashPlan(identity, 'esp32c3', (image,), verified_signature=True, quiesced=True, **kw)
            cases = [plan(self.a, expected_mac=self.b.base_mac),
                     FlashPlan(self.a, 'esp32s3', (image,), True, self.a.base_mac, True),
                     plan(self.a, expected_mac=self.a.base_mac),
                     plan(self.b, expected_mac=self.b.base_mac)]
            results = run_batch(list(zip(['COM0', 'COM0a', 'COM1', 'COM2'], cases)),
                                lambda port: self.a if port != 'COM2' else self.b, write)
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

    def test_default_plan_is_not_authorized(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'app.bin'
            p.write_bytes(b'image')
            with self.assertRaises(ValueError):
                FlashPlan(self.a, 'esp32c3', (Image(0x10000, p, 5, hashlib.sha256(b'image').hexdigest()),),
                          True, self.a.base_mac).verify('COM1', self.a)

    def test_lease_and_rig_import(self):
        with PortLeases() as leases:
            with leases.acquire('board-a'):
                with self.assertRaises(ValueError):
                    with leases.acquire('board-a'):
                        pass
        rigs = import_rig(Path(__file__).resolve().parents[2] / 'hil' / 'rigs.yaml')
        self.assertIn('bridge', rigs['bench-2026-09-26'].boards)


if __name__ == '__main__':
    unittest.main()
