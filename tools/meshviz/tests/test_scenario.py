"""Scenario runner (D12) tests: validation, step sequencing, journaled
resume/reconcile, honest verdicts, and the headless socket driver."""
import json
import tempfile
import unittest
from pathlib import Path

from routeloom_meshviz import scenario as sc
from routeloom_meshviz.demo import DemoMesh
from routeloom_meshviz.fake_api1 import serve_fake_api1
from routeloom_meshviz.scenario_driver import LocalOps, run as driver_run
from routeloom_meshviz.model import FakeClock

NODE = 'aaaabbbbccccdddd'
BENCH = {'admission': {'profile': 'bench-v1', 'calls_per_minute': 600, 'burst': 8,
                       'charges': ['messages.submit', 'operations.open_epoch'],
                       'client': {'inflight_max': 4, 'run_window_calls': 64,
                                  'run_window_ms': 60000}},
         'store': {'records_max': 4096}}

BASE = {
    'schema': sc.SCHEMA,
    'network': '0000000000000001',
    'limits': {'calls_per_minute': 600},
    'nodes': {NODE: {'role': 'bridge'}},
}


def doc(**over):
    d = dict(BASE)
    d.update(over)
    return d


class ValidateTests(unittest.TestCase):
    def test_schema_and_kind_rules(self):
        self.assertTrue(sc.validate({}))
        bad = doc(steps=[{'kind': 'bogus'}])
        self.assertTrue(any('unknown kind' in e for e in sc.validate(bad)))
        dup = doc(steps=[{'id': 'x', 'kind': 'drain'},
                         {'id': 'x', 'kind': 'drain'}])
        self.assertTrue(any('duplicate id' in e for e in sc.validate(dup)))
        badkey = doc(steps=[{'kind': 'drain', 'nope': 1}])
        self.assertTrue(any('unknown key' in e for e in sc.validate(badkey)))

    def test_targets_and_ids(self):
        bad = doc(steps=[{'kind': 'ping', 'to': 'zz', 'count': 1,
                          'interval_ms': 1000}])
        self.assertTrue(any('bad target' in e for e in sc.validate(bad)))
        ok = doc(steps=[{'kind': 'ping', 'to': NODE, 'count': 1,
                         'interval_ms': 1000}])
        self.assertFalse(sc.validate(ok))

    def test_control_send_display_floor(self):
        over = doc(steps=[{'kind': 'control_send', 'target': NODE,
                           'period_ms': 6000, 'duration_ms': 60_000}])
        errs = sc.validate(over)
        self.assertTrue(any('12/min' in e for e in errs))
        under = doc(steps=[{'kind': 'control_send', 'target': NODE,
                            'period_ms': 5_000, 'duration_ms': 60_000}])
        self.assertFalse(sc.validate(under))

    def test_admission_budget_uses_capacity(self):
        sendy = doc(steps=[{'kind': 'ping', 'to': NODE, 'count': 10,
                            'interval_ms': 1_000}])
        # No capacity, no limits → normal profile 2/min rejects.
        no_limits = dict(sendy)
        no_limits.pop('limits')
        self.assertTrue(sc.validate(no_limits))
        # bench-v1 capacity admits it.
        self.assertFalse(sc.validate(sendy, BENCH))

    def test_store_and_duration_bounds(self):
        big = doc(steps=[{'kind': 'ping', 'to': NODE, 'count': 4096,
                          'interval_ms': 1000}])
        self.assertTrue(any('store holds' in e for e in
                            sc.validate(big, BENCH)))
        long_step = doc(steps=[{'kind': 'drain',
                                'timeout_ms': sc.MAX_DURATION_MS + 1}])
        self.assertTrue(any('duration' in e for e in sc.validate(long_step)))

    def test_cutover_and_dangerous_shapes(self):
        bad = doc(steps=[{'kind': 'cutover', 'expected_site_epoch': 1,
                          'next_site_cert': 'xyz'}])
        self.assertTrue(any('next_site_cert' in e for e in sc.validate(bad)))
        ok = doc(steps=[{'kind': 'cutover', 'expected_site_epoch': 1,
                         'next_site_cert': 'aabbcc'}])
        self.assertFalse(sc.validate(ok))
        # membership.revoke requires reason + expected_generation.
        thin = doc(steps=[{'kind': 'exclusion', 'target': NODE}])
        errs = sc.validate(thin)
        self.assertTrue(any('reason' in e for e in errs))
        self.assertTrue(any('expected_generation' in e for e in errs))
        bad_reason = doc(steps=[{'kind': 'exclusion', 'target': NODE,
                                 'reason': 'bogus', 'expected_generation': 1}])
        self.assertTrue(any('reason' in e for e in sc.validate(bad_reason)))

    def test_join_policy_shape(self):
        bad = doc(steps=[{'kind': 'join_policy', 'policy': {'bogus': 1}}])
        self.assertTrue(any('unknown policy key' in e for e in sc.validate(bad)))
        bad_mode = doc(steps=[{'kind': 'join_policy',
                               'policy': {'decision_mode': 'bogus'}}])
        self.assertTrue(any('decision_mode' in e for e in sc.validate(bad_mode)))
        bad_range = doc(steps=[{'kind': 'join_policy',
                                'policy': {'decision_timeout_ms': 100}}])
        self.assertTrue(any('decision_timeout_ms' in e
                            for e in sc.validate(bad_range)))
        ok = doc(steps=[{'kind': 'join_policy',
                         'policy': {'zero_touch_open': True,
                                    'decision_mode': 'external',
                                    'decision_timeout_ms': 2000}}])
        self.assertFalse(sc.validate(ok))


def _drive(runner, reply_fn, ticks=4_000, step_ms=250):
    """Advance the runner; reply_fn(call) -> reply dict or None (dropped)."""
    now = 0
    transcript = []
    for _ in range(ticks):
        for call in runner.due(now):
            transcript.append(call)
            reply = reply_fn(call)
            if reply is not None:
                runner.on_reply(call.tag, reply, now)
        now += step_ms
        if runner.finished:
            break
    return now, transcript


def _ok(result=None):
    return {'ok': True, 'result': result or {}}


class RunnerTests(unittest.TestCase):
    def test_provision_evidence_survives_multi_target_resume(self):
        second = '1111222233334444'
        d = doc(nodes={NODE: {}, second: {}}, steps=[
            {'id': 'flash', 'kind': 'flash_provision',
             'targets': [NODE, second],
             'bundle': {'digest': 'sha256:' + 'a' * 64, 'signature': 'b' * 128}},
        ])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            first = runner.due(0)[0]
            evidence = {'node': NODE,
                        'readback': {'node': NODE, 'kid': 'a' * 64},
                        'inventory': {'node': NODE}}
            runner.on_reply(first.tag, _ok(evidence), 1)
            resumed = sc.ScenarioRunner.resume(
                sc.ScenarioJournal.load(runner.journal.path), now_ms=2,
                capacity={})
            self.assertEqual(resumed.steps[0].detail['provisioned'], [evidence])
            self.assertEqual(resumed.steps[0].detail['targets_left'], [second])

    def test_happy_path(self):
        d = doc(steps=[
            {'id': 'pol', 'kind': 'join_policy',
             'policy': {'zero_touch_open': True}},
            {'id': 'pwr', 'kind': 'sequential_power_on', 'targets': [NODE],
             'settle_ms': 100},
            {'id': 'ping', 'kind': 'ping', 'to': NODE, 'count': 2,
             'interval_ms': 500},
            {'id': 'rep', 'kind': 'report'},
        ])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)

            def reply(call):
                if call.method == 'operations.open_epoch':
                    return _ok({'admission_epoch': '0000000000000001'})
                if call.method == 'messages.submit':
                    return _ok({'operation_id': 'x'})
                return _ok()
            _, transcript = _drive(runner, reply)
            self.assertEqual(runner.state, 'Completed')
            methods = [c.method for c in transcript]
            self.assertIn('join.policy.set', methods)
            self.assertIn('power_on', methods)
            summary = runner.summary()
            self.assertEqual(summary['sends']['admitted'], 2)
            self.assertFalse(summary['incomplete_steps'])
            # Journal is on disk and replayable.
            journal = sc.ScenarioJournal.load(
                Path(td) / f'{runner.journal.run_id}.scenario.json')
            self.assertEqual(journal.state, 'Completed')
            self.assertTrue(journal.entries)

    def test_lost_submit_reconciles_not_admitted(self):
        d = doc(steps=[{'id': 'p', 'kind': 'ping', 'to': NODE, 'count': 1,
                        'interval_ms': 500}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            dropped = []

            def reply(call):
                if call.method == 'operations.open_epoch':
                    return _ok({'admission_epoch': '0000000000000001'})
                if call.method == 'messages.submit' and not dropped:
                    dropped.append(call.tag)
                    return None            # reply lost in transit
                if call.method == 'operations.get_by_key':
                    return {'ok': False, 'error': {'code': 'NOT_FOUND'}}
                return _ok()
            now, transcript = _drive(runner, reply)
            self.assertEqual(runner.state, 'Completed')
            self.assertIn('operations.get_by_key',
                          [c.method for c in transcript])
            verdicts = runner.summary()['sends']['verdicts']
            self.assertEqual(verdicts, {'not_admitted': 1})

    def test_reconcile_finds_admitted_op(self):
        d = doc(steps=[{'id': 'p', 'kind': 'ping', 'to': NODE, 'count': 1,
                        'interval_ms': 500}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            dropped = []

            def reply(call):
                if call.method == 'operations.open_epoch':
                    return _ok({'admission_epoch': '0000000000000001'})
                if call.method == 'messages.submit' and not dropped:
                    dropped.append(call.tag)
                    return None
                if call.method == 'operations.get_by_key':
                    return _ok({'operation_id': 'ffff:0000000000000001'})
                return _ok()
            _drive(runner, reply)
            self.assertEqual(runner.state, 'Completed')
            verdicts = runner.summary()['sends']['verdicts']
            self.assertEqual(verdicts, {'admitted': 1})
            row = runner.results[0]
            self.assertTrue(row.get('reconciled'))

    def test_dangerous_step_timeout_incomplete(self):
        d = doc(steps=[{'id': 'ex', 'kind': 'exclusion', 'target': NODE,
                        'reason': 'removed', 'expected_generation': 1,
                        'timeout_ms': 5_000},
                       {'id': 'd', 'kind': 'drain'}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)

            def reply(call):
                return None                # silence — the transport is dead
            _, transcript = _drive(runner, reply, ticks=200)
            self.assertEqual(runner.state, 'Incomplete')
            steps = {s.id: s.status for s in runner.steps}
            self.assertEqual(steps['ex'], 'incomplete')
            self.assertEqual(steps['d'], 'skipped')
            # The revoke was emitted ONCE — reconcile re-issues it under the
            # same idempotency key, and at most until the step deadline.
            revokes = [c for c in transcript if c.method == 'membership.revoke']
            self.assertTrue(revokes)
            keys = {c.idempotency_key for c in revokes}
            self.assertEqual(len(keys), 1)

    def test_dangerous_reconcile_same_key(self):
        d = doc(steps=[{'id': 'ex', 'kind': 'exclusion', 'target': NODE,
                        'reason': 'removed', 'expected_generation': 1}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            seen = []

            def reply(call):
                seen.append(call.method)
                if call.method == 'membership.revoke' and len(seen) == 1:
                    return None            # first revoke reply is lost
                return _ok({'state': 'revoked'})
            _drive(runner, reply, ticks=400)
            self.assertEqual(runner.state, 'Completed')
            self.assertEqual(seen.count('membership.revoke'), 2)

    def test_optional_step_failure_skips(self):
        d = doc(steps=[{'id': 'o', 'kind': 'rollcall', 'action': 'status',
                        'optional': True},
                       {'id': 'd', 'kind': 'drain'}])

        def reply(call):
            if call.method == 'lab.rollcall.status':
                return {'ok': False, 'error': {'code': 'NO_ROLLCALL'}}
            return _ok()
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _drive(runner, reply)
            self.assertEqual(runner.state, 'Completed')
            self.assertEqual(runner.steps[0].status, 'skipped')

    def test_resume_mid_run(self):
        d = doc(steps=[{'id': 'p', 'kind': 'ping', 'to': NODE, 'count': 4,
                        'interval_ms': 500}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            now = 0
            submits = 0
            for _ in range(200):
                for call in runner.due(now):
                    if call.method == 'operations.open_epoch':
                        runner.on_reply(call.tag,
                                        _ok({'admission_epoch': '0000000000000001'}),
                                        now)
                    elif call.method == 'messages.submit':
                        submits += 1
                        if submits <= 2:
                            runner.on_reply(call.tag,
                                            _ok({'operation_id': f'id{submits}'}),
                                            now)
                        # third+ submits stay unanswered — the crash lands here
                if submits >= 3:
                    break
                now += 250
            self.assertEqual(submits, 3)

            journal = sc.ScenarioJournal.load(
                Path(td) / f'{runner.journal.run_id}.scenario.json')
            resumed = sc.ScenarioRunner.resume(journal, now_ms=now + 30_000)
            self.assertEqual(resumed.epoch, '0000000000000001')
            # The ledger kept the in-flight row; the runner continues at 4.
            self.assertEqual(len(resumed.results), 3)
            self.assertEqual(resumed.steps[0].next_index, 3)

            def reply(call):
                if call.method == 'operations.get_by_key':
                    return _ok({'operation_id': 'id3'})
                if call.method == 'messages.submit':
                    return _ok({'operation_id': 'id4'})
                return _ok()
            _drive(resumed, reply)
            self.assertEqual(resumed.state, 'Completed')
            verdicts = resumed.summary()['sends']['verdicts']
            self.assertEqual(verdicts.get('admitted'), 4)

    def test_resume_replays_rate_limit_retry(self):
        """A RATE_LIMITED submit's paced retry survives a resume: same index,
        same deterministic key — no duplicate planned send."""
        d = doc(steps=[{'id': 'p', 'kind': 'ping', 'to': NODE, 'count': 2,
                        'interval_ms': 500}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            now = 0
            submits = 0
            for _ in range(200):
                for call in runner.due(now):
                    if call.method == 'operations.open_epoch':
                        runner.on_reply(call.tag,
                                        _ok({'admission_epoch': '0000000000000001'}),
                                        now)
                    elif call.method == 'messages.submit':
                        submits += 1
                        if submits == 1:
                            runner.on_reply(call.tag, {
                                'ok': False,
                                'error': {'code': 'RATE_LIMITED',
                                          'detail': {'retry_after_ms': 400}}},
                                now)
                        # submit 2 (the paced retry of index 0) + index 1 stay
                        # unanswered — the crash lands before they resolve
                if submits >= 3:
                    break
                now += 250
            self.assertEqual(submits, 3)

            journal = sc.ScenarioJournal.load(
                Path(td) / f'{runner.journal.run_id}.scenario.json')
            resumed = sc.ScenarioRunner.resume(journal, now_ms=now + 30_000)
            self.assertEqual(resumed.steps[0].next_index, 2)
            self.assertEqual(len(resumed.results), 2)

            keys = []
            def reply(call):
                if call.method == 'messages.submit':
                    keys.append(call.params['key'])
                    return _ok({'operation_id': 'fin'})
                if call.method == 'operations.get_by_key':
                    return _ok({'operation_id': 'fin'})
                return _ok()
            _drive(resumed, reply)
            self.assertEqual(resumed.state, 'Completed')
            verdicts = resumed.summary()['sends']['verdicts']
            self.assertEqual(verdicts.get('admitted'), 2)
            self.assertEqual(resumed.summary()['sends']['planned'], 2)

    def test_resume_recovers_unemitted_step(self):
        """Crash window: 'running' journaled, zero ops — the step's first
        emit never left the runner, so resume re-enters it as a first send."""
        d = doc(steps=[{'id': 'x', 'kind': 'exclusion', 'target': NODE,
                        'reason': 'removed', 'expected_generation': 1},
                       {'id': 'd', 'kind': 'drain'}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            # Drive the first due() so 'running' lands, then drop the emit.
            calls = runner.due(0)
            self.assertEqual(calls[0].method, 'membership.revoke')
            # Simulate the crash BETWEEN the step journal write and the op
            # journal write: strip the op row, keep 'running'.
            journal_path = Path(td) / f'{runner.journal.run_id}.scenario.json'
            doc_j = json.loads(journal_path.read_text())
            doc_j['entries'] = [e for e in doc_j['entries']
                                if e.get('type') != 'op']
            journal_path.write_text(json.dumps(doc_j))

            journal = sc.ScenarioJournal.load(journal_path)
            resumed = sc.ScenarioRunner.resume(journal, now_ms=60_000)
            out = resumed.due(60_000)
            revoke = [c for c in out if c.method == 'membership.revoke']
            self.assertEqual(len(revoke), 1)
            # Same deterministic idempotency key — never a new operation.
            self.assertEqual(revoke[0].idempotency_key,
                             calls[0].idempotency_key)
            for c in out:
                resumed.on_reply(c.tag, _ok(), 60_000)
            _drive(resumed, _ok)
            self.assertEqual(resumed.state, 'Completed')

    def test_formation_wait_pages_past_128(self):
        """A wait for >128 nodes must follow next_after — one page can never
        satisfy the count."""
        d = doc(steps=[{'id': 'fw', 'kind': 'formation_wait', 'count': 200}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            pages = {'n': 0}

            def reply(call):
                if call.method == 'nodes.list':
                    pages['n'] += 1
                    start = (int(call.params['after'], 16) + 1
                             if call.params.get('after') else 0)
                    rows = [{'node': f'{start + i:016x}'}
                            for i in range(128)]
                    out = {'nodes': rows}
                    if start == 0:
                        out['next_after'] = rows[-1]['node']
                    else:
                        out['nodes'] = rows[:80]     # page 2: 128+80 ≥ 200
                    return _ok(out)
                return _ok()
            _, transcript = _drive(runner, reply)
            self.assertEqual(runner.state, 'Completed')
            self.assertEqual(pages['n'], 2)
            self.assertEqual(runner.steps[0].detail['seen'], 208)
            # The second poll carried the cursor.
            afters = [c.params.get('after') for c in transcript
                      if c.method == 'nodes.list']
            self.assertEqual(afters[1], f'{127:016x}')

    def test_reset_rejoin_needs_fresh_evidence(self):
        """A member row that predates the reset is NOT rejoin evidence —
        confirmed_ms must advance past the pre-reset baseline."""
        d = doc(steps=[{'id': 'rr', 'kind': 'reset_rejoin', 'target': NODE}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            member_calls = {'n': 0}

            def reply(call):
                if call.method == 'members.get':
                    member_calls['n'] += 1
                    stale = {'member': {'device_id': NODE, 'state': 'member',
                                        'confirmed_ms': 1000,
                                        'last_seen_ms': 900}}
                    if member_calls['n'] == 1:
                        return _ok(stale)          # baseline snapshot
                    if member_calls['n'] == 2:
                        return _ok(stale)          # unchanged → NOT rejoined
                    fresh = {'member': {'device_id': NODE, 'state': 'member',
                                        'confirmed_ms': 5000,
                                        'last_seen_ms': 5000}}
                    return _ok(fresh)              # advanced → rejoined
                return _ok()
            _drive(runner, reply, ticks=200)
            self.assertEqual(runner.state, 'Completed')
            self.assertEqual(runner.steps[0].status, 'done')
            # Baseline + unchanged poll + fresh poll = 3 members.get calls.
            self.assertEqual(member_calls['n'], 3)

    def test_late_reply_journaled_not_silenced(self):
        """A reply arriving after its op was reconciled lands in the journal
        as late_reply — evidence accrues, verdicts never rewrite."""
        d = doc(steps=[{'id': 'x', 'kind': 'exclusion', 'target': NODE,
                        'reason': 'removed', 'expected_generation': 1,
                        'timeout_ms': 12_000},
                       {'id': 'd', 'kind': 'drain'}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            revoke_tag = None

            def reply(call):
                nonlocal revoke_tag
                if call.method == 'membership.revoke':
                    revoke_tag = call.tag
                    return None            # every revoke reply goes missing
                return _ok()
            _drive(runner, reply, ticks=200)
            self.assertEqual(runner.state, 'Incomplete')
            # The original tag is long settled — feeding it a reply must not
            # crash or reopen the step; it becomes a late_reply journal row.
            runner.on_reply(revoke_tag, _ok({'state': 'revoked'}), 999_000)
            journal = sc.ScenarioJournal.load(
                Path(td) / f'{runner.journal.run_id}.scenario.json')
            lates = [e for e in journal.entries if e.get('type') == 'late_reply']
            self.assertTrue(lates)
            self.assertEqual(lates[0]['tag'], revoke_tag)
            self.assertEqual(runner.steps[0].status, 'incomplete')

    def test_gap_recorded(self):
        d = doc(steps=[{'id': 'd', 'kind': 'drain'}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            runner.due(0)
            runner.due(60_000)             # 60s stall → gap recorded
            runner.due(60_500)
            self.assertTrue(runner.gaps)
            self.assertEqual(runner.state, 'Completed')

    def test_write_report(self):
        d = doc(steps=[{'id': 'p', 'kind': 'ping', 'to': NODE, 'count': 2,
                        'interval_ms': 500},
                       {'id': 'rep', 'kind': 'report',
                        'formats': ['json', 'csv', 'markdown']}])
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(d, td, now_ms=0)
            _drive(runner, lambda call: _ok(
                {'admission_epoch': '0000000000000001'}
                if call.method == 'operations.open_epoch'
                else {'operation_id': f'op-{call.tag}'}))
            out = Path(td) / 'report'
            summary = runner.write_report(out)
            report = json.loads((out / 'report.json').read_text())
            self.assertEqual(report['state'], 'Completed')
            self.assertTrue((out / 'steps.csv').read_text().startswith('step_id'))
            self.assertTrue((out / 'report.md').exists())
            # sends.csv is the ledger verbatim — external aggregation must
            # reproduce the summary's verdict counts exactly.
            sends_csv = (out / 'sends.csv').read_text().splitlines()
            self.assertEqual(sends_csv[0],
                             'step,index,target,key,planned_ms,submit_ms,'
                             'late_ms,result,operation_id')
            rows = sends_csv[1:]
            self.assertEqual(len(rows), summary['sends']['planned'])
            admitted = sum(1 for r in rows if r.split(',')[7] == 'admitted')
            self.assertEqual(admitted, summary['sends']['admitted'])


class DriverTests(unittest.TestCase):
    def test_capture_write_loss_stops_run_with_gap(self):
        with tempfile.TemporaryDirectory() as td:
            runner = sc.ScenarioRunner.arm(doc(steps=[
                {'id': 'record', 'kind': 'record_start', 'path': str(Path(td) / 'capture')},
            ]), td, now_ms=0)
            start = runner.due(0)[0]
            runner.on_reply(start.tag, _ok({'path': str(Path(td) / 'capture')}), 1)
            local = LocalOps()
            clock = FakeClock()
            clock.mono_ns = 1_000_000_000
            clock.unix_ms = 1_000

            class BrokenCapture:
                failed = False

                def add(self, event, at):
                    raise OSError('disk full')

            local.capture = BrokenCapture()
            local.observe('nodes.list', {'source': {'id': 'usb'},
                                         'nodes': []}, runner, clock)
            runner.due(1_001)
            self.assertTrue(runner.gaps)
            self.assertEqual(runner.state, 'Incomplete')

    def test_resume_does_not_claim_unrecorded_tail(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plan = doc(steps=[
                {'id': 'record', 'kind': 'record_start', 'path': str(root / 'capture')},
                {'id': 'wait', 'kind': 'formation_wait', 'count': 1},
            ])
            runner = sc.ScenarioRunner.arm(plan, root / 'journal', now_ms=0)
            call = runner.due(0)[0]
            runner.on_reply(call.tag, _ok({'path': str(root / 'capture')}), 1)
            journal_path = runner.journal.path
            mesh = DemoMesh(4)
            sock_path = root / 'api.sock'
            with serve_fake_api1(sock_path, mesh=mesh):
                resumed, _ = driver_run(None, journal_dir=None,
                                        api1_path=sock_path,
                                        resume_journal=journal_path,
                                        tick_ms=20)
            self.assertEqual(resumed.state, 'Incomplete')
            self.assertTrue(resumed.gaps)

    def test_headless_run_over_socket(self):
        """The runner drives the real API1 line codec against the fake
        server — the same code path the lab uses against the daemon."""
        plan = doc(steps=[
            {'id': 'p', 'kind': 'ping', 'to': '0000000000000002',
             'count': 2, 'interval_ms': 300},
        ])
        with tempfile.TemporaryDirectory() as td:
            plan_path = Path(td) / 'plan.json'
            plan_path.write_text(json.dumps(plan))
            mesh = DemoMesh(4)
            sock_path = Path(td) / 'api.sock'
            with serve_fake_api1(sock_path, mesh=mesh):
                runner, summary = driver_run(
                    plan_path, journal_dir=Path(td) / 'journal',
                    api1_path=sock_path, report_dir=Path(td) / 'report',
                    tick_ms=20)
            self.assertEqual(runner.state, 'Completed')
            self.assertEqual(summary['sends']['admitted'], 2)
            self.assertTrue((Path(td) / 'report' / 'report.json').exists())


if __name__ == '__main__':
    unittest.main()
