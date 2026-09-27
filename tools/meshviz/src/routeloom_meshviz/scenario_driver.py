"""Headless transport for `scenario.py` — Qt-free, drives a ScenarioRunner
against a live daemon's API1 Unix socket.

Channel mapping:
  api1   → `API1 {json}\\n` lines on the daemon socket (request_id = call tag)
  bench  → a synchronous RLB1 round trip via BenchChannel — submit the frame
           over messages.submit, then poll messages.read for the matching
           reply; foreign replies seen while polling are fed back to the
           runner so a device poll never eats another op's answer
  device → D03 ProvisionRunner for provision; `--device-cmd` controls power
           and reset. Missing drivers answer NO_DRIVER.
  local  → record_start opens a capture.Capture boundary; report writes the
           runner's report set

The loop never invents evidence: a dropped reply is a timeout the runner
reconciles, and a failed device driver is an honest step failure.
"""
import hashlib
import json
import select
import shlex
import socket
import sqlite3
import subprocess
import time
from pathlib import Path

from .api1_adapter import LineDecoder, NodesNormalizer, encode_request
from .bench_channel import BenchChannel
from .capture import Capture
from .model import FakeClock
from .scenario import (ScenarioRunner, ScenarioJournal, ScenarioError,
                       load_document_file, validate)


def now_ms() -> int:
    return time.monotonic_ns() // 1_000_000


class Api1Socket:
    """Blocking-connect, nonblocking-poll API1 line client."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.sock.setblocking(False)
        self.decoder = LineDecoder()

    def send(self, call):
        self.sock.sendall(encode_request(call.tag, call.method, call.params))

    def poll(self, timeout_ms: int) -> list:
        """[(request_id, reply)] for replies that arrived within the window."""
        ready, _, _ = select.select([self.sock], [], [], timeout_ms / 1000)
        if not ready:
            return []
        chunk = self.sock.recv(1 << 16)
        if not chunk:
            raise ConnectionError('api1 socket closed')
        return [(r['request_id'], r) for r in self.decoder.feed(chunk)]

    def call(self, method: str, params: dict) -> dict:
        """Synchronous single call — used for capacity.get before arming."""
        tag = f'cli-{method}'
        self.sock.setblocking(True)
        try:
            self.sock.sendall(encode_request(tag, method, params))
            buf = b''
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                chunk = self.sock.recv(1 << 16)
                if not chunk:
                    raise ConnectionError('api1 socket closed')
                buf += chunk
                if b'\n' in buf:
                    break
            replies = self.decoder.feed(buf)
            for reply in replies:
                if reply['request_id'] == tag:
                    return reply
            raise ConnectionError('no reply')
        finally:
            self.sock.setblocking(False)

    def close(self):
        self.sock.close()


class DeviceDriver:
    """D03 provision with readback evidence; external power/reset control."""

    def __init__(self, template: str | None, *, provision_backend=None, nodes=None):
        self.template = template
        self.provision_backend = provision_backend
        self.nodes = {node.lower(): meta for node, meta in (nodes or {}).items()}

    def _pinned_field(self, job, pinned):
        field = self.provision_backend._bundle('field', job, job.chip)
        path = field['path']
        digest = 'sha256:' + hashlib.sha256(
            (path / 'manifest.json').read_bytes()).hexdigest()
        signature = json.loads((path / 'signature.json').read_text(
            encoding='utf-8'))['signature']
        if not isinstance(pinned, dict) or \
                pinned.get('digest') != digest or pinned.get('signature') != signature:
            raise ValueError('field bundle differs from pinned digest/signature')
        return field

    def _provision(self, call):
        from .provision_plan import ProvisionJob, ProvisionRunner
        from .provisioning import ProvisionError, ProvisionJournal

        node = call.params.get('node')
        meta = self.nodes.get(node)
        if self.provision_backend is None:
            return {'ok': False, 'error': {'code': 'NO_DRIVER',
                                           'detail': {'message': 'site/bundles not configured'}}}
        if not isinstance(meta, dict) or not all(
                isinstance(meta.get(key), str) and meta[key]
                for key in ('port', 'chip', 'base_mac', 'role')) or \
                meta['role'] not in ('bridge', 'bench'):
            return {'ok': False, 'error': {'code': 'BAD_TARGET',
                                           'detail': {'message': f'{node}: board metadata missing'}}}
        job = ProvisionJob(meta['port'], meta['chip'], meta['base_mac'],
                           meta['role'], node, steps={'plan': 'done'})
        try:
            self._pinned_field(job, call.params.get('bundle'))
            ProvisionRunner(self.provision_backend, [job]).run_job(job)
            journal = ProvisionJournal.load(
                self.provision_backend._journals() / f'node-{node}.journal.json')
            inventory = journal.latest('inventory')
            if (not job.ready or job.steps.get('inventory') != 'done' or
                    not journal.has('written') or inventory is None or
                    inventory.get('node') != node):
                raise ValueError(f'provision stopped at {job.resume_from or job.next_step()}')
        except (OSError, ValueError, KeyError, RuntimeError, ProvisionError) as exc:
            return {'ok': False, 'error': {'code': 'PROVISION_INCOMPLETE',
                                           'detail': {'message': str(exc)}}}
        return {'ok': True, 'result': {'node': node, 'readback': job.readback,
                                       'inventory': inventory,
                                       'journal': str(journal.path)}}

    def reconcile_provision(self, op):
        """Recover only a completed D03 receipt; never issue another write."""
        from .provision_plan import ProvisionJob
        from .provisioning import ProvisionError, ProvisionJournal

        if self.provision_backend is None or op.method != 'provision':
            return None
        node = op.params.get('node')
        meta = self.nodes.get(node)
        if not isinstance(meta, dict):
            return None
        try:
            job = ProvisionJob(meta['port'], meta['chip'], meta['base_mac'],
                               meta['role'], node)
            field = self._pinned_field(job, op.params.get('bundle'))
            journal = ProvisionJournal.load(
                self.provision_backend._journals() / f'node-{node}.journal.json')
            plan = journal.plan
            readback = journal.latest('readback')
            issued = journal.latest('issued')
            written = journal.latest('written')
            inventory = journal.latest('inventory')
            app = next(entry for entry in field['manifest']['files']
                       if entry['offset'] == 0x10000)
            if (not journal.done or not all((readback, issued, written, inventory)) or
                    plan.get('site_id') != self.provision_backend._load_spec()['site_id'] or
                    plan.get('node_id') != node or
                    plan.get('base_mac', '').lower() != job.base_mac.lower() or
                    plan.get('role') != job.role or
                    plan.get('field_digest') != app['sha256'] or
                    readback.get('node') != node or
                    readback.get('kid') != issued.get('kid') or
                    written.get('node') != node or inventory.get('node') != node):
                return None
        except (OSError, ValueError, KeyError, RuntimeError, ProvisionError):
            return None
        return {'ok': True, 'result': {'node': node, 'readback': readback,
                                       'inventory': inventory,
                                       'journal': str(journal.path)}}

    def execute(self, call) -> dict:
        if call.method == 'provision':
            return self._provision(call)
        if self.template is None:
            return {'ok': False, 'error': {'code': 'NO_DRIVER',
                                         'detail': {'message': 'no --device-cmd given'}}}
        argv = [part.format(op=call.method, node=call.params.get('node', ''),
                            bundle_digest=(call.params.get('bundle') or {})
                            .get('digest', ''))
                for part in shlex.split(self.template)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {'ok': False, 'error': {'code': 'DRIVER_FAILED',
                                           'detail': {'message': str(exc)}}}
        if proc.returncode != 0:
            return {'ok': False, 'error': {'code': 'DRIVER_FAILED',
                                           'detail': {'message': proc.stderr.strip() or
                                                       f'rc={proc.returncode}'}}}
        return {'ok': True, 'result': {'node': call.params.get('node'),
                                       'stdout': proc.stdout.strip()[:2000]}}


class LocalOps:
    """record_start → Capture boundary; report → the run's report set."""

    def __init__(self, report_dir=None):
        self.capture = None
        self.normalizer = NodesNormalizer(connection=0, source='scenario')
        self.report_dir = report_dir
        self.written = []

    def execute(self, call, runner: ScenarioRunner, clock: FakeClock) -> dict:
        if call.method == 'record_start':
            path = call.params.get('path')
            if not path:
                return {'ok': False, 'error': {'code': 'NO_PATH',
                                               'detail': {'message': 'record_start.path'}}}
            try:
                self.capture = Capture(Path(path),
                                       f'scenario-{runner.journal.run_id[:8]}')
                # Provenance for replay: which run/profile produced this capture.
                meta = {'scenario_run_id': runner.journal.run_id,
                        'scenario_schema': runner.doc.get('schema'),
                        'network': runner.network,
                        'admission_profile': (runner.capacity.get('admission')
                                              or {}).get('profile')}
                for k, v in meta.items():
                    if v is not None:
                        self.capture.db.execute(
                            'INSERT OR REPLACE INTO metadata VALUES (?,?)',
                            (k, json.dumps(v)))
                self.capture.db.commit()
            except (OSError, ValueError, sqlite3.Error) as exc:
                return {'ok': False, 'error': {'code': 'CAPTURE_FAILED',
                                               'detail': {'message': str(exc)}}}
            return {'ok': True, 'result': {'path': str(path)}}
        if call.method == 'report':
            out = Path(call.params.get('path') or self.report_dir or
                       f'scenario-report-{runner.journal.run_id[:8]}')
            runner.write_report(out)
            self.written.append(str(out))
            return {'ok': True, 'result': {'written': [str(out)]}}
        return {'ok': False, 'error': {'code': 'UNKNOWN_LOCAL',
                                       'detail': {'message': call.method}}}

    def observe(self, method: str, result: dict, runner: ScenarioRunner,
                clock: FakeClock):
        """Feed api1 observations into an open capture — nodes.list snapshots
        become the replayable record."""
        if self.capture is None or not isinstance(result, dict):
            return
        if method == 'nodes.list':
            try:
                events = self.normalizer.events(result.get('source') or {},
                                                result.get('nodes') or [],
                                                clock.unix_ms)
                for event in events:
                    self.capture.add(event, clock)
            except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
                self.recording_loss(runner, clock, exc)

    def recording_loss(self, runner: ScenarioRunner, clock: FakeClock, error):
        reason = f'recording lost: {error}'
        tick = clock.mono_ns // 1_000_000
        runner.recording_loss(tick, reason)

    def close(self):
        if self.capture is not None:
            self.capture.close()
            self.capture = None


def _fetch_capacity(api1: Api1Socket) -> dict:
    reply = api1.call('capacity.get', {})
    if reply.get('ok'):
        return reply['result']
    return {}


def run(plan_path, *, journal_dir, api1_path, device_cmd=None,
        site_dir=None, bundles_dir=None, provision_backend=None,
        report_dir=None, resume_journal=None, tick_ms=100):
    """Drive a scenario to terminal state. Returns (runner, summary)."""
    try:
        api1 = Api1Socket(api1_path)
    except OSError as exc:
        raise ScenarioError('api1_unreachable',
                            f'{api1_path}: {exc}') from exc
    try:
        capacity = _fetch_capacity(api1)
        if resume_journal:
            journal = ScenarioJournal.load(resume_journal)
            runner = ScenarioRunner.resume(journal, now_ms=now_ms(),
                                           capacity=capacity)
        else:
            doc = load_document_file(plan_path)
            errors = validate(doc, capacity)
            if errors:
                raise ScenarioError('invalid_plan', '; '.join(errors))
            runner = ScenarioRunner.arm(doc, journal_dir, now_ms=now_ms(),
                                        capacity=capacity)
        if provision_backend is None and site_dir and bundles_dir:
            from .device import RealBoards
            from .provisioning import LabProvisionBackend
            provision_backend = LabProvisionBackend(
                site_dir=site_dir, bundles_dir=bundles_dir, boards=RealBoards())
        device = DeviceDriver(device_cmd, provision_backend=provision_backend,
                              nodes=runner.doc.get('nodes'))
        local = LocalOps(report_dir)
        clock = FakeClock()
        if resume_journal and any(
                step.kind == 'record_start' and step.status == 'done'
                for step in runner.steps) and not runner.finished:
            clock.mono_ns = time.monotonic_ns()
            clock.unix_ms = int(time.time() * 1000)
            local.recording_loss(runner, clock,
                                 'capture cannot continue after process restart')
        if resume_journal:
            for op in list(runner.outstanding.values()):
                if op.channel == 'device' and op.method == 'provision':
                    receipt = device.reconcile_provision(op)
                    if receipt is not None:
                        runner.on_reply(op.tag, receipt, now_ms())
        # The bench channel shares the API1 socket; replies it sees that
        # belong to other in-flight ops are fed back into the runner.
        bench = BenchChannel(api1, runner.network)

        def feed(tag, reply):
            runner.on_reply(tag, reply, tick_now)
        try:
            while not runner.finished:
                clock.mono_ns = time.monotonic_ns()
                clock.unix_ms = int(time.time() * 1000)
                tick_now = clock.mono_ns // 1_000_000
                if local.capture is not None and local.capture.failed \
                        and not runner.stop_reason:
                    local.recording_loss(runner, clock, 'capture writer failed')
                try:
                    calls = runner.due(tick_now)
                except ScenarioError:
                    raise
                except Exception as exc:
                    runner.journal.record({'type': 'runner_fault',
                                           'ms': tick_now,
                                           'detail': str(exc)})
                    runner.abort(f'runner fault: {exc}')
                    continue
                for call in calls:
                    if call.channel == 'api1':
                        try:
                            api1.send(call)
                        except OSError:
                            runner.on_reply(call.tag, None, tick_now)
                    elif call.channel == 'bench':
                        runner.on_reply(call.tag, bench.execute(call, feed),
                                        tick_now)
                    elif call.channel == 'device':
                        runner.on_reply(call.tag, device.execute(call), tick_now)
                    else:
                        runner.on_reply(call.tag,
                                        local.execute(call, runner, clock), tick_now)
                try:
                    for tag, reply in api1.poll(tick_ms):
                        if reply.get('ok'):
                            local.observe(_method_of(runner, tag),
                                          reply.get('result'), runner, clock)
                        runner.on_reply(tag, reply, tick_now)
                except (ConnectionError, OSError):
                    for tag in list(runner.outstanding):
                        op = runner.outstanding[tag]
                        if op.channel == 'api1':
                            runner.on_reply(tag, None, tick_now)
                    runner.abort('api1 connection lost')
        finally:
            local.close()
        if report_dir:
            runner.write_report(report_dir)
        return runner, runner.summary()
    finally:
        api1.close()


def _method_of(runner, tag):
    op = runner.outstanding.get(tag) or next(
        (o for o in runner.ops if o.tag == tag), None)
    return op.method if op else ''


def validate_plan(plan_path, api1_path=None) -> list[str]:
    """Static long-plan validation; capacity.get is consulted when reachable."""
    doc = load_document_file(plan_path)
    capacity = {}
    if api1_path:
        try:
            sock = Api1Socket(api1_path)
        except OSError as exc:
            raise ScenarioError('api1_unreachable',
                                f'{api1_path}: {exc}') from exc
        try:
            capacity = _fetch_capacity(sock)
        finally:
            sock.close()
    return validate(doc, capacity)
