"""BenchChannel tests — RLB1 command/reply round trips over a scripted API1
transport (DemoMesh carries a fake bench_node; nothing here invents
evidence — a missed reply is BENCH_NO_REPLY)."""
import unittest

from routeloom_meshviz import rlb1
from routeloom_meshviz.bench_channel import BenchChannel
from routeloom_meshviz.demo import DemoMesh, FakeMethodError
from routeloom_meshviz.model import FakeClock


class FakeSocket:
    """send()/poll() shim over DemoMesh — matches Api1Socket's surface."""

    def __init__(self, mesh):
        self.mesh = mesh
        self.pending = []

    def send(self, call):
        try:
            result = self.mesh.handle(call.method, call.params)
            reply = {'v': 1, 'request_id': call.tag, 'ok': True,
                     'result': result}
        except FakeMethodError as exc:
            reply = {'v': 1, 'request_id': call.tag, 'ok': False,
                     'error': {'code': exc.code,
                               'detail': {'message': exc.code, **exc.detail}}}
        self.pending.append((call.tag, reply))

    def poll(self, timeout_ms):
        out, self.pending = self.pending, []
        return out


def _mesh():
    clock = FakeClock(10_000_000_000, 1_800_000_000_000)
    mesh = DemoMesh(4, clock=lambda: (clock.mono_ns // 1_000_000,
                                      clock.unix_ms))
    mesh.RATE_PER_MIN = 6000            # tests never wait on admission
    return mesh, clock


def _call(method, **params):
    class C:
        pass
    c = C()
    c.method = method
    c.params = params
    return c


NETWORK = '0000000000000001'
SRC = '0000000000000002'
DST = '0000000000000003'
RUN = 'aabbccddeeff00112233445566778899'


class ChannelTest(unittest.TestCase):
    def test_hello_capabilities(self):
        mesh, _ = _mesh()
        ch = BenchChannel(FakeSocket(mesh), NETWORK)
        reply = ch.execute(_call('hello', node=SRC, run=RUN, seq=1),
                           lambda t, r: None)
        self.assertTrue(reply['ok'])
        caps = reply['result']
        self.assertEqual(caps['boot_incarnation'], 1 + int(SRC, 16))
        self.assertIn(rlb1.Opcode.PEER_SEND_STATUS, caps['opcodes'])

    def test_start_then_status_then_stop(self):
        mesh, clock = _mesh()
        ch = BenchChannel(FakeSocket(mesh), NETWORK)
        hello = lambda node: ch.execute(_call('hello', node=node, run=RUN,
                                              seq=0), lambda t, r: None)
        src_boot = hello(SRC)['result']['boot_incarnation']
        dst_boot = hello(DST)['result']['boot_incarnation']
        start = ch.execute(_call(
            'peer_send_start', node=SRC, run=RUN, seq=1,
            expected_boot=src_boot, expected_dest_boot=dst_boot,
            destination=DST, sequence_begin=1, count=8, payload_len=16,
            seed=7, interval_ms=100, ttl_ms=5000, max_inflight=1),
            lambda t, r: None)
        self.assertTrue(start['ok'])
        self.assertEqual(start['result']['result'], rlb1.PS_STARTED)
        self.assertEqual(start['result']['state'], rlb1.GEN_RUNNING)
        # Mid-run query: still RUNNING.
        q = ch.execute(_call('peer_send_status', node=SRC, run=RUN, seq=2),
                       lambda t, r: None)
        self.assertEqual(q['result']['state'], rlb1.GEN_RUNNING)
        # Advance the fake clock past the run — the query reports COMPLETE.
        clock.mono_ns += 2_000_000_000
        q = ch.execute(_call('peer_send_status', node=SRC, run=RUN, seq=3),
                       lambda t, r: None)
        self.assertEqual(q['result']['state'], rlb1.GEN_COMPLETE)
        self.assertEqual(q['result']['submitted'], 8)
        self.assertEqual(q['result']['delivered'], 8)
        # Destination counters are collected separately.
        count = ch.execute(_call('count_get', node=DST, run=RUN, seq=4),
                           lambda t, r: None)
        self.assertEqual(count['result']['unique_packets'], 8)
        self.assertEqual(count['result']['state'], rlb1.COUNT_ACTIVE)

    def test_stale_boot_is_refused_not_started(self):
        mesh, _ = _mesh()
        ch = BenchChannel(FakeSocket(mesh), NETWORK)
        reply = ch.execute(_call(
            'peer_send_start', node=SRC, run=RUN, seq=1,
            expected_boot=0xDEAD, expected_dest_boot=0,
            destination=DST, sequence_begin=1, count=4, payload_len=16,
            seed=0, interval_ms=100, ttl_ms=5000, max_inflight=1),
            lambda t, r: None)
        self.assertTrue(reply['ok'])
        self.assertEqual(reply['result']['result'], rlb1.PS_STALE_BOOT)

    def test_same_seq_command_dedups(self):
        mesh, _ = _mesh()
        ch = BenchChannel(FakeSocket(mesh), NETWORK)
        # Each runner attempt carries its own op_tag → distinct submit keys;
        # the DEVICE dedups by (run, seq) and re-answers flagged DUPLICATE.
        def attempt(n):
            return _call('peer_send_start', node=SRC, run=RUN, seq=1,
                         op_tag=f'op-{n}',
                         expected_boot=0, expected_dest_boot=0,
                         destination=DST, sequence_begin=1, count=4,
                         payload_len=16, seed=0, interval_ms=100, ttl_ms=5000,
                         max_inflight=1)
        first = ch.execute(attempt(1), lambda t, r: None)
        second = ch.execute(attempt(2), lambda t, r: None)
        self.assertEqual(first['result']['result'], rlb1.PS_STARTED)
        self.assertEqual(second['result']['result'], rlb1.PS_STARTED)
        self.assertTrue(second['result']['flags'] & rlb1.FLAG_DUPLICATE)
        # Exactly one run exists — the re-issue never minted another.
        self.assertEqual(len(mesh.bench_runs), 1)

    def test_no_reply_is_unknown_not_success(self):
        mesh, _ = _mesh()
        sock = FakeSocket(mesh)

        class Silent(mesh.__class__):
            def _bench_dispatch(self, node, msg, mono):
                pass                     # the device never answers

        mesh.__class__ = Silent
        ch = BenchChannel(sock, NETWORK, reply_timeout_ms=300)
        reply = ch.execute(_call('hello', node=SRC, run=RUN, seq=1),
                           lambda t, r: None)
        self.assertFalse(reply['ok'])
        self.assertEqual(reply['error']['code'], 'BENCH_NO_REPLY')

    def test_foreign_reply_is_fed_back_not_consumed(self):
        mesh, _ = _mesh()
        ch = BenchChannel(FakeSocket(mesh), NETWORK)
        seen = []
        ch.execute(_call('hello', node=SRC, run=RUN, seq=1),
                   lambda t, r: seen.append((t, r)))
        self.assertEqual(seen, [])
        # A foreign api1 reply mid-exchange is forwarded via feed — inject
        # one by having send() queue an extra reply.
        sock = FakeSocket(mesh)
        real_send = sock.send

        def injected(call):
            real_send(call)
            sock.pending.append(('other-tag', {'v': 1, 'request_id':
                                               'other-tag', 'ok': True,
                                               'result': {}}))
        sock.send = injected
        ch2 = BenchChannel(sock, NETWORK)
        ch2.execute(_call('hello', node=DST, run=RUN, seq=1),
                    lambda t, r: seen.append((t, r)))
        self.assertIn('other-tag', [t for t, _ in seen])


if __name__ == '__main__':
    unittest.main()
