"""Qt-free tests: join timeline, rollcall budget, site poller, supervisor and provision plan."""
import json
import os
import subprocess
import time
import tempfile
import unittest
from pathlib import Path

from routeloom_meshviz.capture import Capture
from routeloom_meshviz.demo_site import APPROVE_MS, CONFIRM_MS, JOIN_STAGGER_MS, SITE_ID, DemoSiteMesh
from routeloom_meshviz.fake_api1 import FakeAPI1
from routeloom_meshviz.live_monitor import (JoinTimeline, SitePoller, read_status_text,
                                            rollcall_interval_floor_ms, rollcall_summary,
                                            route_switches, transitions)
from routeloom_meshviz.model import FakeClock
from routeloom_meshviz.playback import CaptureReader
from routeloom_meshviz.provisioning import (ContractBackend, FakeProvisionBackend, ProvisionRunner,
                                            auto_approval_text, job_status_text, plan_jobs,
                                            valid_lab_node_id)
from routeloom_meshviz.site_supervisor import (SiteConfig, SiteLock, SiteSupervisor, lab_site_init,
                                               verify_daemon, write_lab_spec, write_self_acl)

A, B, GW = f'{2:016x}', f'{3:016x}', f'{1:016x}'
KID_A = 'aa' * 32
S = 1_000_000_000


def request(node, created, kid=KID_A, attempt=1):
    return {'join_request_id': f'jr-{attempt:016x}', 'device_id': node, 'kid': kid,
            'created_ms': created, 'attempt': attempt, 'state': 'awaiting'}


def member(node, approved, confirmed=None, kid=KID_A, state='member'):
    return {'device_id': node, 'kid': kid, 'state': state, 'generation': 1,
            'confirm_state': 'active' if confirmed else 'allowed_unconfirmed',
            'approved_ms': approved, 'confirmed_ms': confirmed}


class RollcallBudgetTests(unittest.TestCase):
    def test_interval_floor_matches_design_table(self):
        # design-devflow §6.5: 10% budget, retry factor 1.5, root included in N.
        self.assertEqual({n: rollcall_interval_floor_ms(n) for n in (5, 9, 10, 20, 50, 100)},
                         {5: 2000, 9: 2000, 10: 2065, 20: 4360, 50: 11243, 100: 22715})

    def test_summary_keeps_missing_values_unknown(self):
        summary = rollcall_summary({'state': 'running', 'counts': {'delivered': 0}})
        self.assertEqual(summary['counts']['delivered'], 0)
        self.assertIsNone(summary['counts']['missing'])
        self.assertIsNone(summary['effective_interval_ms'])
        self.assertIsNone(rollcall_summary(None))


class JoinTimelineTests(unittest.TestCase):
    def test_ledger_milestones_come_only_from_their_own_evidence(self):
        timeline = JoinTimeline()
        timeline.on_requests([request(A, 1000)])
        self.assertEqual(timeline.states()[A], '検証済申請')
        timeline.on_members([member(A, 1500)])
        # An approval commit alone is not membership.
        self.assertEqual(timeline.states()[A], '承認')
        timeline.on_members([member(A, 1500, 1900)])
        self.assertEqual(timeline.states()[A], 'Member')
        row = timeline.rows[A]
        self.assertEqual(row.fields['request_verified_at'].at_unix_ms, 1000)
        self.assertEqual(row.fields['approval_committed_at'].at_unix_ms, 1500)
        self.assertEqual(row.fields['confirmed_at'].at_unix_ms, 1900)
        for name in ('power_on_at', 'boot_at', 'member_adopted_at', 'first_response_observed_at',
                     'route_first_at', 'route_stable_at'):
            self.assertIsNone(row.fields.get(name), name)

    def test_join_relay_is_kept_apart_from_membership(self):
        timeline = JoinTimeline()
        item = request(A, 1000)
        timeline.on_requests([{**item, 'via': {'gateway': GW, 'proxy': B}}])
        self.assertEqual(timeline.rows[A].join_proxy, B)
        timeline.on_requests([{**request(B, 1000), 'via': {'proxy': '0' * 16}}])
        self.assertIsNone(timeline.rows[B].join_proxy)

    def test_first_evidence_wins_and_new_kid_starts_a_fresh_row(self):
        timeline = JoinTimeline()
        timeline.on_requests([request(A, 1000)])
        timeline.on_requests([request(A, 5000, attempt=2)])
        self.assertEqual(timeline.rows[A].fields['request_verified_at'].at_unix_ms, 1000)
        timeline.on_requests([request(A, 9000, kid='bb' * 32)])
        row = timeline.rows[A]
        self.assertEqual(row.fields['request_verified_at'].at_unix_ms, 9000)
        self.assertEqual(row.identity_changes, 1)

    def test_old_request_cannot_replace_current_member_identity(self):
        timeline = JoinTimeline()
        current = 'bb' * 32
        timeline.on_members([member(A, 2000, 3000, kid=current)])
        timeline.on_requests([request(A, 1000, kid=KID_A)])
        self.assertEqual(timeline.rows[A].kid, current)
        self.assertEqual(timeline.rows[A].state(), 'Member')

    def test_gateway_sighting_is_never_membership(self):
        timeline = JoinTimeline()
        timeline.on_routes({'mono_ns': S, 'unix_ms': 1000, 'gateway': GW,
                            'routes': {GW: None, A: A}})
        self.assertEqual(timeline.states()[A], '観測のみ')
        self.assertEqual(timeline.rows[A].fields['route_first_at'].at_unix_ms, 1000)
        self.assertIsNone(timeline.rows[A].fields.get('power_on_at'))
        self.assertIsNone(timeline.rows[A].fields.get('first_response_observed_at'))

    def observe(self, timeline, t_s, hop, connection=1):
        timeline.begin_session(connection)
        return timeline.on_routes({'mono_ns': t_s * S, 'unix_ms': t_s * 1000, 'gateway': GW,
                                   'routes': {A: hop}})

    def test_route_stable_needs_three_snapshots_five_seconds_and_an_app_response(self):
        timeline = JoinTimeline()
        for t in (0, 2, 4, 6):
            self.observe(timeline, t, B)
        # Stable next hop for 6 s but no app response: no stable time.
        self.assertIsNone(timeline.rows[A].fields.get('route_stable_at'))
        timeline.on_statuses([{'node': A, 'first_status_received_ms': 7000,
                               'last_status_received_ms': 7000}], 7 * S)
        changed = self.observe(timeline, 8, B)
        self.assertEqual(timeline.rows[A].fields['route_stable_at'].at_unix_ms, 8000)
        self.assertEqual([c['field'] for c in changed], ['route_stable_at'])
        self.assertEqual(timeline.rows[A].fields['first_response_observed_at'].at_unix_ms, 7000)

    def test_response_before_the_current_route_does_not_make_it_stable(self):
        timeline = JoinTimeline()
        self.observe(timeline, 0, A)
        timeline.on_statuses([{'node': A, 'last_status_received_ms': 1000}], 1 * S)
        for t in (2, 4, 6, 8):
            self.observe(timeline, t, B)  # switched at 2 s: the 1 s response predates it
        self.assertIsNone(timeline.rows[A].fields.get('route_stable_at'))

    def test_route_switch_and_reconnect_restart_the_streak(self):
        timeline = JoinTimeline()
        for t in (0, 2):
            self.observe(timeline, t, B)
        self.observe(timeline, 4, A)
        self.assertEqual(len(timeline.rows[A].route_streak), 1)
        self.observe(timeline, 6, A, connection=2)
        self.assertEqual(len(timeline.rows[A].route_streak), 1)
        self.observe(timeline, 8, None, connection=2)
        self.assertEqual(timeline.rows[A].route_streak, [])
        self.assertEqual(route_switches({A: B}, {A: A}), [(A, B, A)])
        self.assertEqual(transitions({A: '承認'}, {A: 'Member', B: '未参加'}), [(A, '承認', 'Member')])

    def test_group_totals_do_not_create_first_response(self):
        timeline = JoinTimeline()
        timeline.on_members([member(A, 1000, 1200)])
        # A rollcall result with delivered counts but no individual STATUS.
        timeline.on_statuses([], S)
        self.assertIsNone(timeline.rows[A].fields.get('first_response_observed_at'))

    def test_power_marker_is_manual_and_bounded(self):
        timeline = JoinTimeline()
        changed = timeline.mark_power_on(A, 500)
        self.assertEqual(changed[0]['source'], 'operator')
        self.assertEqual(timeline.states()[A], '未参加')
        self.assertEqual(timeline.mark_power_on('bad', 600), [])

    def test_table_is_bounded(self):
        timeline = JoinTimeline(max_rows=2)
        timeline.on_requests([request(f'{i:016x}', i) for i in range(1, 5)])
        self.assertEqual(len(timeline.rows), 2)
        self.assertTrue(timeline.truncated)

    def test_recorded_milestones_replay_without_inference(self):
        timeline = JoinTimeline()
        changed = timeline.on_requests([request(A, 1000)]) + timeline.on_members([member(A, 1500)])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'c'
            clock = FakeClock(1, 1)
            with Capture(path, 'c') as capture:
                for change in changed:
                    capture.add({'kind': 'join_milestone', 'source': 'meshlab-live', 'payload': change},
                                clock)
                capture.add({'kind': 'rollcall_status', 'source': 'meshlab-live',
                             'payload': {'state': 'running', 'poll_seq': 3}}, clock)
            reader = CaptureReader(path)
            events = reader.site_events()
            reader.close()
        self.assertEqual([e['kind'] for e in events], ['join_milestone'] * 2 + ['rollcall_status'])
        replayed = JoinTimeline()
        for event in events[:2]:
            replayed.apply_recorded(event['payload'])
        self.assertEqual(replayed.rows[A].fields['approval_committed_at'].at_unix_ms, 1500)
        self.assertIsNone(replayed.rows[A].fields.get('confirmed_at'))


def ok(result):
    return {'v': 1, 'request_id': 'x', 'ok': True, 'result': result}


def err(code, **detail):
    return {'v': 1, 'request_id': 'x', 'ok': False,
            'error': {'code': code, 'detail': detail, 'retryable': bool(detail)}}


ALL = {'site.status': True, 'join.requests.list': True, 'members.list': True,
       'lab.rollcall.status': True, 'lab.inventory.list': True}


class SitePollerTests(unittest.TestCase):
    def test_only_advertised_methods_are_read(self):
        poller = SitePoller()
        poller.reset({'site.status': True})
        self.assertEqual([m for _, m, _ in poller.due(0)], ['site.status'])
        self.assertEqual(read_status_text(poller, 'rollcall'), '未対応（daemon が広告していない）')

    def test_stale_reply_from_previous_connection_is_dropped(self):
        poller = SitePoller()
        poller.reset(ALL)
        tag = poller.due(0)[0][0]
        poller.reset(ALL)
        self.assertIsNone(poller.on_reply(tag, ok({'site_id': 'x'}), 1))
        self.assertNotIn('site', poller.results)

    def test_retry_after_is_honoured(self):
        poller = SitePoller()
        poller.reset({'lab.rollcall.status': True})
        tag = poller.due(0)[0][0]
        poller.on_reply(tag, err('BUSY', retry_after_ms=30_000), 10)
        self.assertEqual(poller.due(5_000), [])
        self.assertEqual(poller.due(29_999), [])
        self.assertEqual(len(poller.due(30_010)), 1)

    def test_unknown_method_and_missing_authority_are_distinct(self):
        poller = SitePoller()
        poller.reset(ALL)
        tags = {m: t for t, m, _ in poller.due(0)}
        poller.on_reply(tags['lab.rollcall.status'], err('UNKNOWN_METHOD'), 1)
        poller.on_reply(tags['site.status'], err('SITE_AUTHORITY_UNAVAILABLE'), 1)
        poller.on_reply(tags['members.list'], None, 1)
        self.assertFalse(poller.supported('lab.rollcall.status'))
        self.assertIn('未対応', read_status_text(poller, 'rollcall'))
        self.assertIn('Site Authority なし', read_status_text(poller, 'site'))
        self.assertIn('不明', read_status_text(poller, 'members'))
        poller.reset(None)
        self.assertEqual(read_status_text(poller, 'site'), '未接続')
        self.assertEqual(poller.due(100_000), [])

    def test_member_pages_are_joined_before_use(self):
        poller = SitePoller()
        poller.reset({'members.list': True})
        tag = poller.due(0)[0][0]
        self.assertIsNone(poller.on_reply(tag, ok({'members': [member(A, 1)], 'next_after': A}), 1))
        (tag2, method, params), = poller.due(2)
        self.assertEqual((method, params['after']), ('members.list', A))
        kind, result = poller.on_reply(tag2, ok({'members': [member(B, 2)], 'next_after': None}), 3)
        self.assertEqual([m['device_id'] for m in result['members']], [A, B])

    def test_oversized_final_member_page_is_rejected(self):
        poller = SitePoller()
        poller.reset({'members.list': True})
        tag = poller.due(0)[0][0]
        self.assertIsNone(poller.on_reply(tag, ok({'members': [member(A, 1)] * 1025,
                                                  'next_after': None}), 1))
        self.assertNotIn('members', poller.results)
        self.assertEqual(poller.errors['members'], 'invalid')

    def test_timeout_is_unknown_and_reissued(self):
        poller = SitePoller()
        poller.reset({'site.status': True})
        poller.due(0)
        self.assertEqual(poller.due(5_000), [])
        self.assertEqual(len(poller.due(10_001)), 1)
        self.assertIn('不明', read_status_text(poller, 'site'))


class FakeProcess:
    def __init__(self, argv):
        self.argv = argv
        self.pid = 4242
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def caps(version=1, **methods):
    return ok({'api': {'version': 1}, 'caps_version': version,
               'methods': {'site.status': True, **methods}})


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.site_dir = Path(self.tmp.name) / 'site'
        self.site_dir.mkdir()
        self.answer = None  # None → no daemon on the socket
        self.processes = []

    def probe(self, path):
        if self.answer is None:
            raise ConnectionRefusedError('no daemon')
        return self.answer

    def launcher(self, argv, **kw):
        process = FakeProcess(argv)
        self.processes.append(process)
        return process

    def supervisor(self):
        return SiteSupervisor(probe=self.probe, launcher=self.launcher)

    def config(self, **kw):
        return SiteConfig(self.site_dir, self.site_dir / 'api1.sock', **kw)

    def test_attach_binds_site_and_refuses_another_site_on_the_socket(self):
        sup = self.supervisor()
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        sup.attach(self.config(), 0)
        sup.tick(0)
        self.assertEqual((sup.state, sup.session, sup.site_id), ('ready', 1, SITE_ID))
        # The daemon is replaced by another site's daemon on the same path.
        self.answer = (caps(), ok({'site_id': 'ffffffffffffffff'}))
        sup.tick(5_000)
        self.assertEqual(sup.state, 'mismatch')
        self.assertEqual(sup.site_id, SITE_ID)
        self.assertEqual(sup.methods, {})
        self.assertEqual(self.processes, [])  # an attached daemon is never started or stopped

    def test_expected_site_id_is_checked_before_first_use(self):
        sup = self.supervisor()
        self.answer = (caps(), ok({'site_id': 'ffffffffffffffff'}))
        sup.attach(self.config(expected_site_id=SITE_ID), 0)
        sup.tick(0)
        self.assertEqual(sup.state, 'mismatch')

    def test_attached_usb_gateway_must_belong_to_site(self):
        self.answer = (caps(), ok({'site_id': SITE_ID, 'gateways': [GW],
                                   'usb': {'attached': True}}))
        sup = SiteSupervisor(probe=self.probe, launcher=self.launcher,
                             usb_probe=lambda path: B)
        sup.attach(self.config(), 0)
        sup.tick(0)
        self.assertEqual(sup.state, 'mismatch')
        self.assertEqual(sup.session, 0)
        sup.stop()

    def test_unversioned_capabilities_are_refused(self):
        self.assertIsNotNone(verify_daemon(caps(version=None), ok({'site_id': SITE_ID}), None)[1])
        self.assertIsNotNone(verify_daemon(ok({'api': {'version': 1}, 'caps_version': 1, 'methods': {}}),
                                           ok({'site_id': SITE_ID}), None)[1])

    def test_boolean_api_version_and_nonhex_site_id_are_refused(self):
        self.assertIsNotNone(verify_daemon(ok({'api': {'version': True}, 'caps_version': 1,
                                               'methods': {'site.status': True}}),
                                           ok({'site_id': SITE_ID}), None)[1])
        self.assertIsNotNone(verify_daemon(caps(), ok({'site_id': 'zzzzzzzzzzzzzzzz'}), None)[1])

    def test_malformed_probe_reply_is_rejected_without_worker_exception(self):
        self.assertIsNotNone(verify_daemon(ok([]), ok({'site_id': SITE_ID}), None)[1])
        self.assertIsNotNone(verify_daemon(caps(), ok([]), None)[1])

    def test_owned_daemon_restarts_with_backoff_and_new_session(self):
        sup = self.supervisor()
        sup.start(self.config(device=None), 0)
        self.assertEqual(sup.state, 'starting')
        argv = self.processes[0].argv
        self.assertEqual(argv[1:5], ['--socket', str(self.site_dir / 'api1.sock'),
                                     '--site-authority', str(self.site_dir)])
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        sup.tick(500)
        self.assertEqual((sup.state, sup.session), ('ready', 1))
        self.processes[0].returncode = 101
        self.answer = None
        sup.tick(1_000)
        self.assertEqual(sup.state, 'reconnecting')
        self.assertIn('exit 101', sup.reason)
        sup.tick(1_500)
        self.assertEqual(len(self.processes), 1)  # waits for the back-off
        sup.tick(2_000)
        self.assertEqual(len(self.processes), 2)
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        sup.tick(2_500)
        self.assertEqual((sup.state, sup.session), ('ready', 2))
        sup.stop()
        self.assertTrue(self.processes[1].terminated)
        self.assertEqual(sup.state, 'stopped')

    def test_restart_limit_fails_instead_of_looping(self):
        sup = self.supervisor()
        sup.start(self.config(), 0)
        now = 0
        for _ in range(10):
            if sup.state == 'failed':
                break
            self.processes[-1].returncode = 1
            now += 20_000
            sup.tick(now)
            now += 20_000
            sup.tick(now)
        self.assertEqual(sup.state, 'failed')
        self.assertIn('再起動上限', sup.reason)

    def test_start_refuses_when_a_daemon_already_answers(self):
        sup = self.supervisor()
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        sup.start(self.config(), 0)
        self.assertEqual(sup.state, 'failed')
        self.assertEqual(self.processes, [])

    def test_second_supervisor_cannot_attach_to_same_site(self):
        if os.name != 'posix':
            self.skipTest('flock is Linux/POSIX only')
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        first, second = self.supervisor(), self.supervisor()
        first.attach(self.config(), 0)
        first.tick(0)
        self.addCleanup(first.stop)
        second.attach(self.config(), 0)
        self.assertEqual(second.state, 'failed')

    def test_attached_daemon_loss_reconnects_without_spawning(self):
        sup = self.supervisor()
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        sup.attach(self.config(), 0)
        sup.tick(0)
        self.answer = None
        for t in (2_000, 4_000, 6_000):
            sup.tick(t)
        self.assertEqual(sup.state, 'reconnecting')
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        sup.tick(8_000)
        self.assertEqual((sup.state, sup.session), ('ready', 2))
        sup.stop()
        self.assertEqual(self.processes, [])

    def test_owned_unresponsive_daemon_is_stopped_before_restart(self):
        sup = self.supervisor()
        sup.start(self.config(), 0)
        self.answer = (caps(), ok({'site_id': SITE_ID}))
        sup.tick(500)
        self.assertEqual(sup.state, 'ready')
        self.answer = None
        for at in (2_500, 4_500, 6_500):
            sup.tick(at)
        self.assertEqual(sup.state, 'reconnecting')
        self.assertTrue(self.processes[0].terminated)
        self.assertIsNone(sup.process)
        sup.tick(7_500)
        self.assertEqual(len(self.processes), 2)
        sup.stop()

    def test_one_supervisor_per_site_directory(self):
        first = SiteLock(self.site_dir)
        first.acquire()
        self.addCleanup(first.release)
        sup = self.supervisor()
        sup.start(self.config(), 0)
        self.assertEqual(sup.state, 'failed')
        self.assertIn('別の Mesh Lab', sup.reason)
        self.assertEqual(self.processes, [])

    def test_lab_spec_is_random_valid_and_reused_for_resume(self):
        spec_path = Path(self.tmp.name) / 'lab.lab-spec.json'
        write_lab_spec(spec_path, gateway=GW, channel=6)
        first = json.loads(spec_path.read_text())
        self.assertEqual(first['format'], 'routeloom-lab-site-spec-v1')
        self.assertEqual(first['gateways'], [GW])
        self.assertEqual(len(first['site_id']), 16)
        self.assertEqual(len(first['network_low32']), 8)
        self.assertEqual(spec_path.stat().st_mode & 0o777, 0o600)
        write_lab_spec(spec_path, gateway=GW, channel=6)
        self.assertEqual(json.loads(spec_path.read_text()), first)
        with self.assertRaises(ValueError):
            write_lab_spec(Path(self.tmp.name) / 'x.json', gateway='0' * 16, channel=6)

    def test_lab_site_init_reports_unsupported_cli(self):
        def run(argv, **kw):
            self.assertEqual(argv[1:3], ['lab-site-init', '--spec'])
            return subprocess.CompletedProcess(argv, 1, '', 'usage: ...\nError: "invalid command"')
        result = lab_site_init('routeloomctl', 'spec.json', 'out', run=run)
        self.assertEqual(result['state'], 'unsupported')
        missing = lab_site_init('/nonexistent/routeloomctl', 'spec.json', 'out')
        self.assertEqual(missing['state'], 'unsupported')


REPO = Path(__file__).resolve().parents[3]
HOST_BIN = Path(os.environ.get('ROUTELOOM_HOST_BIN_DIR', REPO / 'host' / 'target' / 'debug'))


@unittest.skipUnless((HOST_BIN / 'routeloomctl').exists() and (HOST_BIN / 'routeloom-host').exists(),
                     'routeloomctl/routeloom-host not built')
class RealDaemonTests(unittest.TestCase):
    """lab-site-init → self ACL → SiteSupervisor starts, verifies and stops the real daemon."""
    def test_created_lab_site_is_supervised_end_to_end(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        spec = write_lab_spec(tmp / 'lab.lab-spec.json', gateway=GW, channel=3)
        created = lab_site_init(str(HOST_BIN / 'routeloomctl'), spec, tmp / 'lab')
        self.assertEqual(created['state'], 'created', created)
        # A second run over the completed site is refused, never re-minted.
        again = lab_site_init(str(HOST_BIN / 'routeloomctl'), spec, tmp / 'lab')
        self.assertNotEqual(again['state'], 'created')
        site_id = json.loads(spec.read_text())['site_id']
        acl = write_self_acl(tmp / 'lab', json.loads(spec.read_text())['network_low32'])
        sup = SiteSupervisor()
        config = SiteConfig(tmp / 'lab', tmp / 'lab' / 'ipc' / 'api1.sock',
                            daemon=str(HOST_BIN / 'routeloom-host'), acl_file=acl,
                            expected_site_id=site_id)
        sup.start(config, time.monotonic_ns() // 1_000_000)
        self.addCleanup(sup.stop)
        deadline = time.monotonic() + 15
        while sup.state != 'ready' and time.monotonic() < deadline and sup.state != 'failed':
            sup.tick(time.monotonic_ns() // 1_000_000)
            time.sleep(0.1)
        self.assertEqual(sup.state, 'ready', sup.reason)
        self.assertEqual(sup.site_status['purpose'], 'development')
        self.assertIn('無効', auto_approval_text(sup.site_status))
        process = sup.process
        sup.stop()
        self.assertIsNotNone(process.returncode)
        self.assertEqual(sup.state, 'stopped')


class ProvisionTests(unittest.TestCase):
    def boards(self):
        return [{'board': 'p1', 'chip': 'esp32s3', 'base_mac': 'aa:00', 'role': 'bridge', 'node_id': '1'},
                {'board': 'p2', 'chip': 'esp32c3', 'base_mac': 'aa:01', 'role': 'bench', 'node_id': '2'}]

    def test_plan_rejects_duplicates_reserved_ids_and_unprobed_boards(self):
        self.assertIsNone(valid_lab_node_id('ffffffffffff0001'))
        self.assertIsNone(valid_lab_node_id('0'))
        boards = self.boards() + [
            {'board': 'p3', 'chip': None, 'base_mac': None, 'role': 'bench', 'node_id': '2'},
            {'board': 'p4', 'chip': 'x', 'base_mac': 'aa:04', 'role': 'bridge', 'node_id': 'ffffffffffff0001'}]
        _, errors = plan_jobs(boards)
        self.assertIn('NodeId 0000000000000002 が重複', errors['p2'])
        self.assertIn('ROM 検査で MAC を確認していない', errors['p3'])
        self.assertTrue(any('group 名前空間' in r for r in errors['p4']))
        self.assertTrue(any('bridge は site ごとに 1 台' in r for r in errors['p1']))

    def test_contract_backend_is_unsupported_and_never_ready(self):
        jobs, errors = plan_jobs(self.boards())
        self.assertEqual(errors, {})
        runner = ProvisionRunner(ContractBackend(), jobs)
        for job in jobs:
            runner.run_job(job)
            self.assertFalse(job.ready)
            self.assertEqual(job.steps['preflight'], 'unsupported')
            self.assertNotIn('keygen', job.steps)
            self.assertIn('未対応', job_status_text(job))

    def test_fake_backend_is_ready_only_after_readback_and_joins_on_member_evidence(self):
        jobs, _ = plan_jobs(self.boards())
        runner = ProvisionRunner(FakeProvisionBackend(), jobs)
        for job in jobs:
            runner.run_job(job)
        self.assertTrue(all(job.ready for job in jobs))
        self.assertEqual(jobs[1].steps['join'], 'waiting')
        timeline = JoinTimeline()
        timeline.on_members([member(jobs[1].node_id, 10, kid=jobs[1].readback['kid'])])
        runner.observe_join(timeline.rows)
        self.assertFalse(jobs[1].joined)
        timeline.on_members([member(jobs[1].node_id, 10, 20, kid='ff' * 32)])
        runner.observe_join(timeline.rows)
        self.assertFalse(jobs[1].joined)
        timeline.on_members([member(jobs[1].node_id, 10, 20, kid=jobs[1].readback['kid'])])
        runner.observe_join(timeline.rows)
        self.assertTrue(jobs[1].joined)

    def test_sealed_board_needs_attention_and_is_not_reprovisioned(self):
        jobs, _ = plan_jobs(self.boards())
        runner = ProvisionRunner(FakeProvisionBackend({'p2': 'sealed'}), jobs)
        runner.run_job(jobs[1])
        self.assertEqual(jobs[1].steps['status'], 'attention')
        self.assertNotIn('keygen', jobs[1].steps)
        self.assertFalse(jobs[1].ready)
        self.assertIn('要対応', job_status_text(jobs[1]))

    def test_readback_mismatch_is_not_ready(self):
        class Wrong(FakeProvisionBackend):
            def run(self, step, job):
                result = super().run(step, job)
                if step == 'readback':
                    result.data['node_id'] = f'{99:016x}'
                return result
        jobs, _ = plan_jobs(self.boards())
        ProvisionRunner(Wrong(), jobs).run_job(jobs[0])
        self.assertFalse(jobs[0].ready)
        self.assertEqual(jobs[0].resume_from, 'readback')

    def test_cancel_stops_between_steps_and_resumes_there(self):
        jobs, _ = plan_jobs(self.boards())
        calls = []

        class Counting(FakeProvisionBackend):
            def run(self, step, job):
                calls.append(step)
                return super().run(step, job)
        runner = ProvisionRunner(Counting(), jobs, should_cancel=lambda: len(calls) >= 3)
        runner.run_job(jobs[0])
        self.assertEqual(calls, ['preflight', 'setup', 'status'])
        self.assertEqual(jobs[0].resume_from, 'keygen')
        runner.should_cancel = None
        runner.run_job(jobs[0])
        self.assertTrue(jobs[0].ready)

    def test_auto_approval_follows_purpose_mode_and_enrollment_window(self):
        def text(purpose, mode, active):
            return auto_approval_text({'purpose': purpose, 'policy': {
                'decision_mode': mode, 'lab_enrollment_active': active}})
        self.assertIn('有効', text('development', 'lab_inventory', True))
        self.assertIn('閉鎖中', text('development', 'lab_inventory', False))
        self.assertIn('無効', text('development', 'kguard', False))
        self.assertIn('不可', text('production', 'lab_inventory', True))
        self.assertIn('不明', auto_approval_text(None))


class DemoSiteTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock(0, 1_790_000_000_000)
        self.mesh = DemoSiteMesh(4, clock=lambda: (self.clock.mono_ns // 1_000_000, self.clock.unix_ms))

    def test_nodes_join_one_by_one_with_ledger_evidence(self):
        self.assertEqual([n['node'] for n in self.mesh.gateway_nodes()], [GW])
        self.clock.advance(JOIN_STAGGER_MS + APPROVE_MS)
        members = self.mesh.handle('members.list', {})['members']
        self.assertEqual([m['confirm_state'] for m in members], ['active', 'allowed_unconfirmed'])
        self.clock.advance(CONFIRM_MS)
        self.assertIn(A, [n['node'] for n in self.mesh.gateway_nodes()])

    def test_rollcall_waits_for_members_and_refuses_a_second_run_with_retry_after(self):
        api = FakeAPI1(mesh=self.mesh)
        self.mesh.handle('lab.rollcall.start', {'desired_interval_ms': 2000})
        self.assertEqual(self.mesh.handle('lab.rollcall.status', {})['state'], 'waiting_members')
        reply = api._reply(b'API1 {"v":1,"request_id":"r","method":"lab.rollcall.start",'
                           b'"params":{"desired_interval_ms":2000}}')
        self.assertIn(b'"retry_after_ms":1000', reply)
        self.clock.advance(3000)
        status = self.mesh.handle('lab.rollcall.status', {})
        self.assertEqual(status['state'], 'running')
        self.assertEqual(status['counts']['active_members'], 3)
        self.assertTrue(all(s['first_status_received_ms'] for s in status['statuses']))


if __name__ == '__main__':
    unittest.main()
