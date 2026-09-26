"""Headless transport for `scenario.py` — Qt-free, drives a ScenarioRunner
against a live daemon's API1 Unix socket.

Channel mapping:
  api1   → `API1 {json}\\n` lines on the daemon socket (request_id = call tag)
  device → a `--device-cmd` template executed per op, rc==0 means ok; without
           a driver every device op answers NO_DRIVER so dangerous steps
           degrade to `incomplete` instead of silently passing
  local  → record_start opens a capture.Capture boundary; report writes the
           runner's report set

The loop never invents evidence: a dropped reply is a timeout the runner
reconciles, and a failed device driver is an honest step failure.
"""
import json
import select
import shlex
import socket
import subprocess
import time
from pathlib import Path

from .api1_adapter import LineDecoder, NodesNormalizer, encode_request
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
    """`--device-cmd 'tpl {op} {node} {bundle_digest}'` — one subprocess per
    device op. Exit 0 = ok. No driver = an explicit NO_DRIVER failure."""

    def __init__(self, template: str | None):
        self.template = template

    def execute(self, call) -> dict:
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
            except (OSError, ValueError) as exc:
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

    def observe(self, method: str, result: dict, clock: FakeClock):
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
            except (ValueError, RuntimeError):
                pass                    # capture failures never block the run

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
        device = DeviceDriver(device_cmd)
        local = LocalOps(report_dir)
        clock = FakeClock()
        try:
            while not runner.finished:
                clock.mono_ns = time.monotonic_ns()
                clock.unix_ms = int(time.time() * 1000)
                tick_now = clock.mono_ns // 1_000_000
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
                    elif call.channel == 'device':
                        runner.on_reply(call.tag, device.execute(call), tick_now)
                    else:
                        runner.on_reply(call.tag,
                                        local.execute(call, runner, clock), tick_now)
                try:
                    for tag, reply in api1.poll(tick_ms):
                        runner.on_reply(tag, reply, tick_now)
                        if reply.get('ok'):
                            local.observe(_method_of(runner, tag),
                                          reply.get('result'), clock)
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
