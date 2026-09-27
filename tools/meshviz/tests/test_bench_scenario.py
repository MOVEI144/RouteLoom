"""peer_send/soak scenario tests (D10/D12): the steps drive device
generators over the bench channel — the runner must never emit a
host-side messages.submit for the data plane, and reports must carry
device-sourced counters, never inferred success."""
import tempfile
import unittest
from pathlib import Path

from routeloom_meshviz import scenario as sc
from routeloom_meshviz import rlb1

SRC = '0000000000000002'
DST = '0000000000000003'
SRC2 = '0000000000000004'
DST2 = '0000000000000005'

BENCH = {'admission': {'profile': 'bench-v1', 'calls_per_minute': 600,
                       'burst': 8,
                       'charges': ['messages.submit', 'operations.open_epoch'],
                       'client': {'inflight_max': 4, 'run_window_calls': 64,
                                  'run_window_ms': 60000}},
         'store': {'records_max': 4096}}

BASE = {'schema': sc.SCHEMA, 'network': '0000000000000001',
        'limits': {'calls_per_minute': 600},
        'nodes': {SRC: {'role': 'bench'}, DST: {'role': 'bench'},
                  SRC2: {'role': 'bench'}, DST2: {'role': 'bench'}}}


def doc(**over):
    d = dict(BASE)
    d.update(over)
    return d


def _ok(result=None):
    return {'ok': True, 'result': result or {}}


def caps(boot):
    return _ok({'app_protocol': 1, 'app_version': 1, 'max_unicast_body': 96,
                'max_group_body': 95, 'max_command_body': 64, 'run_slots': 1,
                'reply_queue': 2, 'generator_max_inflight': 1,
                'boot_incarnation': boot, 'firmware_digest': 0,
                'config_digest': 0, 'opcodes': [1, 2, 0x50, 0x51, 0x52, 0x21],
                'flags': rlb1.FLAG_RESPONSE})


def status(result, state, **counters):
    body = {'result': result, 'state': state, 'planned': 0, 'submitted': 0,
            'admitted': 0, 'delivered': 0, 'failed': 0, 'unknown': 0,
            'first_ms': 0, 'last_ms': 0, 'flags': rlb1.FLAG_RESPONSE}
    body.update(counters)
    return _ok(body)


def count_status(unique, state=rlb1.COUNT_ACTIVE):
    return _ok({'state': state, 'unique_packets': unique, 'unique_bytes': 0,
                'duplicates': 0, 'crc_invalid': 0, 'first_ms': 0,
                'last_ms': 0, 'window_base': unique, 'window': 0,
                'flags': rlb1.FLAG_RESPONSE})


def _drive(runner, reply_fn, ticks=8_000, step_ms=200):
    """Advance the runner; reply_fn(call) -> reply dict or None (dropped)."""
    now = 0
    transcript = []
    for _ in range(ticks):
        for call in runner.due(now):
            transcript.append(call)
            reply = reply_fn(call, now)
            if reply is not None:
                runner.on_reply(call.tag, reply, now)
        now += step_ms
        if runner.finished:
            break
    return now, transcript


def bench_reply_factory(completes_after_ms=60_000):
    """Simulated bench_node replies at the on_reply boundary: hello→caps,
    start→STARTED, polls→RUNNING until the run's virtual end, count_get→
    the destination's own counter."""
    runs = {}

    def reply(call, now):
        if call.channel != 'bench':
            return _ok()
        p = call.params
        if call.method == 'hello':
            return caps(0xB0071D0000 + int(p['node'], 16))
        if call.method == 'peer_send_start':
            runs[p['run']] = {'t0': now, 'count': p['count'],
                              'interval_ms': p['interval_ms'], 'dst': DST}
            return status(rlb1.PS_STARTED, rlb1.GEN_RUNNING,
                          planned=p['count'])
        if call.method == 'peer_send_status':
            run = runs.get(p['run'])
            if run is None:
                return status(rlb1.PS_NOT_RUNNING, rlb1.GEN_IDLE)
            sent = min(run['count'],
                       max(0, (now - run['t0']) // run['interval_ms']))
            state = (rlb1.GEN_COMPLETE if now - run['t0'] >=
                     min(run['count'] * run['interval_ms'], 60_000)
                     else rlb1.GEN_RUNNING)
            return status(rlb1.PS_QUERY, state, planned=run['count'],
                          submitted=sent, admitted=sent, delivered=sent)
        if call.method == 'peer_send_stop':
            run = runs.get(p['run'])
            if run is None:
                return status(rlb1.PS_NOT_RUNNING, rlb1.GEN_IDLE)
            sent = min(run['count'],
                       max(0, (now - run['t0']) // run['interval_ms']))
            return status(rlb1.PS_STOPPED, rlb1.GEN_STOPPED,
                          planned=run['count'], submitted=sent,
                          admitted=sent, delivered=sent)
        if call.method == 'count_get':
            # The destination counts what the run's generator delivered.
            run = runs.get(p['run'])
            sent = 0 if run is None else min(
                run['count'], max(0, (now - run['t0']) // run['interval_ms']))
            return count_status(sent,
                                rlb1.COUNT_ACTIVE if run else
                                rlb1.COUNT_UNKNOWN)
        return _ok()
    return reply


class ValidateBenchTests(unittest.TestCase):
    def test_pairs_required_and_bounded(self):
        bad = doc(steps=[{'kind': 'peer_send', 'count': 4,
                          'interval_ms': 500}])
        self.assertTrue(any('pairs' in e for e in sc.validate(bad)))
        bad = doc(steps=[{'kind': 'peer_send',
                          'pairs': [[SRC, 'nope']], 'count': 4,
                          'interval_ms': 500}])
        self.assertTrue(any('bad pair' in e for e in sc.validate(bad)))
        ok = doc(steps=[{'kind': 'peer_send',
                         'pairs': [[SRC, DST]], 'count': 4,
                         'interval_ms': 500, 'timeout_ms': 120_000}])
        self.assertFalse(sc.validate(ok))

    def test_peer_send_count_bounded_by_device(self):
        over = doc(steps=[{'kind': 'peer_send', 'pairs': [[SRC, DST]],
                           'count': 65, 'interval_ms': 500,
                           'timeout_ms': 300_000}])
        self.assertTrue(any('count' in e for e in sc.validate(over)))
        # A run can never exceed the 60 s device bound.
        over = doc(steps=[{'kind': 'peer_send', 'pairs': [[SRC, DST]],
                           'count': 64, 'interval_ms': 2000,
                           'timeout_ms': 300_000}])
        self.assertTrue(any('60' in e or 'run bound' in e
                            for e in sc.validate(over)))

    def test_soak_deadline_must_cover_drain(self):
        tight = doc(steps=[{'kind': 'soak', 'pairs': [[SRC, DST]],
                            'duration_ms': 120_000, 'interval_ms': 1000,
                            'timeout_ms': 120_000}])
        self.assertTrue(any('timeout' in e for e in sc.validate(tight)))
        ok = doc(steps=[{'kind': 'soak', 'pairs': [[SRC, DST]],
                         'duration_ms': 120_000, 'interval_ms': 1000,
                         'timeout_ms': 240_000}])
        self.assertFalse(sc.validate(ok))


class PeerSendTests(unittest.TestCase):
    def test_peer_send_uses_device_generator_not_host_submit(self):
        d = doc(steps=[{'id': 'pe', 'kind': 'peer_send',
                        'pairs': [[SRC, DST]], 'count': 4,
                        'interval_ms': 200, 'timeout_ms': 60_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _, transcript = _drive(runner, bench_reply_factory())
            self.assertEqual(runner.state, 'Completed')
            # The step emitted ONLY bench-channel commands — the host never
            # put a data packet on the wire.
            subs = [c for c in transcript
                    if c.channel == 'api1' and c.method == 'messages.submit']
            self.assertEqual(subs, [])
            bench = [c for c in transcript if c.channel == 'bench']
            methods = [c.method for c in bench]
            self.assertEqual(methods[:3],
                             ['hello', 'hello', 'peer_send_start'])
            self.assertIn('peer_send_status', methods)
            self.assertEqual(methods[-1], 'count_get')
            summary = runner.summary()
            runs = summary['bench']['runs']
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]['outcome'], 'complete')
            self.assertEqual(runs[0]['status']['delivered'], 4)
            self.assertEqual(runs[0]['dst_count']['unique_packets'], 4)
            self.assertEqual(summary['bench']['generator']['delivered'], 4)
            self.assertEqual(
                summary['bench']['destination']['unique_packets'], 4)

    def test_peer_send_multi_pair_is_sequential(self):
        d = doc(steps=[{'id': 'pe', 'kind': 'peer_send',
                        'pairs': [[SRC, DST], [SRC2, DST2]], 'count': 2,
                        'interval_ms': 100, 'timeout_ms': 120_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _, transcript = _drive(runner, bench_reply_factory())
            self.assertEqual(runner.state, 'Completed')
            runs = runner.summary()['bench']['runs']
            self.assertEqual(len(runs), 2)
            # Two runs → two distinct run_uuids, one generator at a time.
            self.assertNotEqual(runs[0]['run'], runs[1]['run'])
            starts = [c for c in transcript
                      if c.channel == 'bench'
                      and c.method == 'peer_send_start']
            self.assertEqual(len(starts), 2)
            self.assertNotEqual(starts[0].params['node'],
                                starts[1].params['node'])

    def test_peer_send_busy_is_evidence_not_pass(self):
        busy = bench_reply_factory()
        orig = busy

        def reply(call, now):
            if call.method == 'peer_send_start':
                return status(rlb1.PS_BUSY, rlb1.GEN_RUNNING)
            return orig(call, now)

        d = doc(steps=[{'id': 'pe', 'kind': 'peer_send',
                        'pairs': [[SRC, DST]], 'count': 2,
                        'interval_ms': 100, 'timeout_ms': 60_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _drive(runner, reply)
            self.assertEqual(runner.state, 'Incomplete')
            run = runner.summary()['bench']['runs'][0]
            self.assertEqual(run['outcome'], 'busy')
            # No terminal evidence → never a pass.
            self.assertIn('pe', runner.summary()['incomplete_steps'])

    def test_peer_send_stale_boot_fails(self):
        def reply(call, now):
            if call.method == 'hello':
                return caps(5)
            if call.method == 'peer_send_start':
                return status(rlb1.PS_STALE_BOOT, rlb1.GEN_IDLE)
            return _ok()
        d = doc(steps=[{'id': 'pe', 'kind': 'peer_send',
                        'pairs': [[SRC, DST]], 'count': 2,
                        'interval_ms': 100, 'timeout_ms': 60_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _drive(runner, reply)
            self.assertEqual(runner.state, 'Failed')
            self.assertEqual(runner.summary()['bench']['runs'][0]['outcome'],
                             'refused')

    def test_lost_status_reply_reissues_same_seq(self):
        seen_status = []
        factory = bench_reply_factory()

        def reply(call, now):
            if call.method == 'peer_send_status' and len(seen_status) == 0:
                seen_status.append(call.params['seq'])
                return None                # reply lost
            return factory(call, now)

        d = doc(steps=[{'id': 'pe', 'kind': 'peer_send',
                        'pairs': [[SRC, DST]], 'count': 64,
                        'interval_ms': 900, 'timeout_ms': 120_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _, transcript = _drive(runner, reply)
            self.assertEqual(runner.state, 'Completed')
            statuses = [c for c in transcript
                        if c.method == 'peer_send_status']
            # The reconcile re-issue keeps the same (run, seq) identity.
            seqs = [c.params['seq'] for c in statuses]
            self.assertIn(seen_status[0], seqs[1:])
            recon = [o for o in runner.ops if o.reconciles]
            self.assertTrue(recon)

    def test_run_report_csv_carries_device_counters(self):
        d = doc(steps=[{'id': 'pe', 'kind': 'peer_send',
                        'pairs': [[SRC, DST]], 'count': 3,
                        'interval_ms': 150, 'timeout_ms': 60_000},
                       {'id': 'rep', 'kind': 'report'}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            report_dir = Path(td) / 'out'
            factory = bench_reply_factory()

            def reply(call, now):
                if call.channel == 'local' and call.method == 'report':
                    runner.write_report(report_dir)
                    return _ok({'written': [str(report_dir)]})
                return factory(call, now)
            _drive(runner, reply)
            csv = (report_dir / 'bench_runs.csv').read_text()
            self.assertIn('outcome', csv.splitlines()[0])
            self.assertIn('complete', csv)
            self.assertIn(',3,3,3,3,0,0,', csv)   # planned..unknown


class SoakTests(unittest.TestCase):
    def test_soak_runs_bounded_intervals_then_drains(self):
        d = doc(steps=[{'id': 'soak', 'kind': 'soak',
                        'pairs': [[SRC, DST]], 'duration_ms': 6_000,
                        'interval_ms': 200, 'timeout_ms': 120_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _, transcript = _drive(runner, bench_reply_factory())
            self.assertEqual(runner.state, 'Completed')
            subs = [c for c in transcript if c.method == 'messages.submit']
            self.assertEqual(subs, [])
            runs = runner.summary()['bench']['runs']
            # 6 s at 200 ms spacing → 30 packets per run — multiple bounded
            # intervals may run inside the window.
            self.assertTrue(runs)
            for r in runs:
                self.assertIn(r['outcome'],
                              ('complete', 'stopped'))
            accum = runner.summary()['bench']['generator']
            self.assertGreater(accum['submitted'], 0)
            # Stopped runs legitimately plan more than they submit.
            self.assertGreaterEqual(accum['planned'], accum['submitted'])
            # Outcome counters never exceed what was put on the wire.
            self.assertLessEqual(
                accum['delivered'] + accum['failed'] + accum['unknown'],
                accum['submitted'])

    def test_soak_max_data_messages_stops_early(self):
        d = doc(steps=[{'id': 'soak', 'kind': 'soak',
                        'pairs': [[SRC, DST]], 'duration_ms': 600_000,
                        'interval_ms': 50, 'max_data_messages': 10,
                        'timeout_ms': 900_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _, transcript = _drive(runner, bench_reply_factory())
            self.assertEqual(runner.state, 'Completed')
            accum = runner.summary()['bench']['generator']
            # The bound cuts the soak after the run that crosses it — the
            # overshoot is at most one bounded run's worth of submissions.
            self.assertLessEqual(accum['submitted'],
                                 10 + sc.GEN_MAX_COUNT)
            # A 600 s soak at this interval would take many more runs.
            self.assertLessEqual(len(runner.summary()['bench']['runs']), 2)

    def test_soak_stop_drains_live_run_when_budget_spent(self):
        # Long-run spacing keeps the generator RUNNING at poll time, so the
        # spent budget is observed mid-run → the runner drains it with an
        # explicit peer_send_stop.
        factory = bench_reply_factory()
        d = doc(steps=[{'id': 'soak', 'kind': 'soak',
                        'pairs': [[SRC, DST]], 'duration_ms': 600_000,
                        'interval_ms': 5_000, 'max_data_messages': 5,
                        'timeout_ms': 900_000}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _, transcript = _drive(runner, factory)
            self.assertEqual(runner.state, 'Completed')
            stops = [c for c in transcript
                     if c.method == 'peer_send_stop']
            self.assertTrue(stops)
            run = runner.summary()['bench']['runs'][0]
            self.assertEqual(run['outcome'], 'stopped')


if __name__ == '__main__':
    unittest.main()
