"""Worker objects moved to QThreads; the GUI thread never blocks on socket, SQLite or USB."""
from collections import deque
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

from PySide6.QtCore import QCoreApplication, QObject, QTimer, Signal, Slot
from PySide6.QtNetwork import QLocalSocket

from ..api1_adapter import LineDecoder, NodesNormalizer, encode_request
from ..capture import Capture
from ..model import State, reduce
from ..playback import CaptureReader

POLL_MS = 2000
REQUEST_TIMEOUT_MS = 10_000
RECONNECT_MS = 3000
SNAPSHOT_MS = 100
HISTORY_POINTS = 2000


class SystemClock:
    """Capture clock: host monotonic ns for ordering, UTC ms for humans."""
    @property
    def mono_ns(self):
        return time.monotonic_ns()

    @property
    def unix_ms(self):
        return time.time_ns() // 1_000_000


def now_unix_ms():
    return time.time_ns() // 1_000_000


def _release(worker):
    # Hand the object (and its timers/sockets) back to the GUI thread before its
    # thread exits, so Python may drop it there without cross-thread timer teardown.
    worker.moveToThread(QCoreApplication.instance().thread())


def public_state(state: State) -> State:
    # Reducer entries are replaced, never mutated, so shallow table copies are immutable views.
    return State(nodes=dict(state.nodes), links=dict(state.links), routes=dict(state.routes),
                 samples=dict(state.samples), gaps=list(state.gaps))


class ApiClient(QObject):
    """API1 over QLocalSocket (Unix socket path): nodes.list polling plus tagged requests."""
    events = Signal(list)
    reply = Signal(str, object)
    status = Signal(dict)

    def __init__(self, path):
        super().__init__()
        self.path = str(path)
        self.socket = None
        self.connection = 0
        self.counter = 0
        self.pending = {}
        self.pages = None
        self.capabilities = None
        self.info = {'connected': False, 'error': None, 'source': None, 'last_poll_unix_ms': None,
                     'methods': {}}

    @Slot()
    def start(self):
        self.socket = QLocalSocket(self)
        self.socket.connected.connect(self._on_connected)
        self.socket.disconnected.connect(self._on_disconnected)
        self.socket.readyRead.connect(self._on_ready)
        self.socket.errorOccurred.connect(self._on_error)
        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self._poll)
        self.watchdog = QTimer(self)
        self.watchdog.timeout.connect(self._expire)
        self.watchdog.start(1000)
        self.reconnect_timer = QTimer(self)
        self.reconnect_timer.setSingleShot(True)
        self.reconnect_timer.timeout.connect(self._connect)
        self._connect()

    def _connect(self):
        self.decoder = LineDecoder()
        self.socket.abort()
        self.socket.connectToServer(self.path)

    def _publish(self, **changes):
        self.info.update(changes)
        self.status.emit(dict(self.info))

    def _on_connected(self):
        self.connection += 1
        self.normalizer = NodesNormalizer(self.connection)
        self.pages = None
        self._publish(connected=True, error=None)
        self._send(('capabilities',), 'capabilities.get', {})
        self._poll()
        self.poll_timer.start(POLL_MS)

    def _on_disconnected(self):
        self.poll_timer.stop()
        self._fail_pending()
        self._publish(connected=False)
        if not self.reconnect_timer.isActive():
            self.reconnect_timer.start(RECONNECT_MS)

    def _on_error(self, error):
        self._publish(connected=False, error=self.socket.errorString())
        self._fail_pending()
        self.poll_timer.stop()
        if not self.reconnect_timer.isActive():
            self.reconnect_timer.start(RECONNECT_MS)

    def _fail_pending(self):
        # Lost replies are reported as None: callers record unknown, never success.
        for kind, _ in list(self.pending.values()):
            if kind[0] == 'user':
                self.reply.emit(kind[1], None)
        self.pending.clear()
        self.pages = None

    def _send(self, kind, method, params):
        if self.socket is None or self.socket.state() != QLocalSocket.LocalSocketState.ConnectedState:
            if kind[0] == 'user':
                self.reply.emit(kind[1], None)
            return
        self.counter += 1
        request_id = f'mv-{self.connection}-{self.counter}'
        self.pending[request_id] = (kind, time.monotonic())
        self.socket.write(encode_request(request_id, method, params))

    @Slot(str, str, dict)
    def request(self, tag, method, params):
        self._send(('user', tag), method, params)

    def _poll(self, after=None):
        if after is None:
            if self.pages is not None:
                return
            self.pages = []
        params = {'limit': 128}
        if after is not None:
            params['after'] = after
        self._send(('nodes',), 'nodes.list', params)

    def _expire(self):
        now = time.monotonic()
        for request_id, (kind, sent) in list(self.pending.items()):
            if (now - sent) * 1000 > REQUEST_TIMEOUT_MS:
                del self.pending[request_id]
                if kind[0] == 'user':
                    self.reply.emit(kind[1], None)
                elif kind[0] == 'nodes':
                    self.pages = None
                    self._publish(error='nodes.list timeout')

    def _on_ready(self):
        try:
            replies = self.decoder.feed(bytes(self.socket.readAll().data()))
        except (ValueError, UnicodeDecodeError) as exc:
            self._publish(error=f'API1 protocol error: {exc}')
            self.socket.abort()
            return
        for response in replies:
            entry = self.pending.pop(response.get('request_id'), None)
            if entry is None:
                continue
            kind = entry[0]
            if kind[0] == 'user':
                self.reply.emit(kind[1], response)
            elif kind[0] == 'capabilities' and response.get('ok'):
                methods = response['result'].get('methods', {})
                self._publish(methods={k: v is True for k, v in methods.items()})
            elif kind[0] == 'nodes':
                self._on_nodes(response)

    def _on_nodes(self, response):
        if self.pages is None:
            return
        if not response.get('ok'):
            self.pages = None
            self._publish(error=f'nodes.list: {response.get("error", {}).get("code")}')
            return
        result = response['result']
        self.pages.extend(result.get('nodes', []))
        if result.get('next_after') and len(self.pages) < 1024:
            self._poll(result['next_after'])
            return
        nodes, self.pages = self.pages, None
        now = now_unix_ms()
        self._publish(source=result.get('source'), last_poll_unix_ms=now, error=None)
        events = self.normalizer.events(result.get('source') or {}, nodes, now)
        if events:
            self.events.emit(events)

    @Slot()
    def stop(self):
        for timer in ('poll_timer', 'watchdog', 'reconnect_timer'):
            if hasattr(self, timer):
                getattr(self, timer).stop()
        if self.socket is not None:
            self._fail_pending()
            self.socket.abort()
        _release(self)


class ModelWorker(QObject):
    """Owns the reducer state, bounded sample history and the single SQLite writer."""
    snapshot = Signal(dict)
    recording = Signal(dict)

    def __init__(self, mode='LIVE'):
        super().__init__()
        self.mode = mode
        self.state = State()
        self.history = {}
        self.capture = None
        self.dirty = True
        self.clock = SystemClock()
        self.trial_events = []

    @Slot()
    def start(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._emit)
        self.timer.start(SNAPSHOT_MS)

    @Slot(list)
    def ingest(self, events):
        for event in events:
            if self.capture is not None:
                try:
                    self.capture.add(event, self.clock)
                except ValueError:
                    # Rejected atomically before insert: a malformed input, not a storage fault.
                    self.state.gaps.append({'reason': 'invalid_event', 'source': event.get('source')})
                    continue
                except (RuntimeError, OSError, sqlite3.Error) as exc:
                    self._recording_failed(exc)
            try:
                reduce(self.state, event)
            except (ValueError, KeyError, TypeError):
                self.state.gaps.append({'reason': 'invalid_event', 'source': event.get('source')})
                continue
            if event['kind'] == 'sample':
                payload = event['payload']
                key = f'{event["scope"]}:{payload["series"]}'
                observed = payload.get('observed_unix_ms')
                self.history.setdefault(key, deque(maxlen=HISTORY_POINTS)).append(
                    (observed if type(observed) is int else now_unix_ms(), payload.get('value')))
            elif event['kind'] in ('trial_run', 'trial_message'):
                self.trial_events.append(event)
        self.dirty = True

    def _recording_failed(self, exc):
        # A failed recorder must not look alive: stop, report, keep the partial capture.
        path = self.capture.path
        try:
            self.capture.close()
        except Exception:
            pass
        self.capture = None
        self.recording.emit({'active': False, 'path': str(path), 'error': str(exc)})

    @Slot(str)
    def start_recording(self, path):
        if self.capture is not None:
            return
        try:
            self.capture = Capture(Path(path), Path(path).stem,
                                   versions={'meshviz': '0.1.0'}, scopes=[])
            # Seed the capture with the current view so a replay starts complete.
            for key, event in self._baseline():
                self.capture.add(event, self.clock)
            self.recording.emit({'active': True, 'path': path, 'error': None, 'events': self.capture.seq})
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            if self.capture is not None:
                self.capture.close()
            self.capture = None
            self.recording.emit({'active': False, 'path': path, 'error': str(exc)})

    def _baseline(self):
        grouped = {}
        for section in ('nodes', 'links', 'routes'):
            for key, claims in self.state.claims.get(section, {}).items():
                scope = key.split(':', 1)[0]
                for source, item in claims.items():
                    clean = {k: v for k, v in item.items() if not k.startswith('_')}
                    sections = grouped.setdefault((source, scope), {'nodes': [], 'links': [], 'routes': []})
                    sections[section].append(clean)
        # Each claim is re-seeded under its own source and epoch as a partial snapshot, so
        # the source's next complete snapshot can still retire it during replay.
        return [(scope, {'kind': 'snapshot', 'scope': scope, 'source': source,
                         'source_epoch': self.state.sources.get(source, (None, None))[0],
                         'payload': {'complete': False, **sections}})
                for (source, scope), sections in grouped.items()]

    @Slot()
    def stop_recording(self):
        if self.capture is None:
            return
        path = str(self.capture.path)
        events = self.capture.seq
        try:
            self.capture.close()
            self.recording.emit({'active': False, 'path': path, 'error': None, 'events': events})
        except Exception as exc:
            self.recording.emit({'active': False, 'path': path, 'error': str(exc), 'events': events})
        self.capture = None

    def _emit(self):
        if self.capture is not None and self.capture.seq:
            self.recording.emit({'active': True, 'path': str(self.capture.path), 'error': None,
                                 'events': self.capture.seq})
        if not self.dirty:
            return
        self.dirty = False
        self.snapshot.emit({'mode': self.mode, 'state': public_state(self.state),
                            'history': {k: list(v) for k, v in self.history.items()},
                            'now_unix_ms': now_unix_ms(), 'now_mono_ns': time.monotonic_ns(),
                            'trial_events': list(self.trial_events)})

    @Slot()
    def stop(self):
        if hasattr(self, 'timer'):
            self.timer.stop()
        self.stop_recording()
        _release(self)


class ReplayWorker(QObject):
    """Plays a capture with a virtual clock; it has no path to any command sink."""
    snapshot = Signal(dict)
    position = Signal(dict)
    failed = Signal(str)

    def __init__(self):
        super().__init__()
        self.reader = None
        self.speed = 1.0
        self.playing = False
        self.seq = 0

    @Slot()
    def start(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(50)

    @Slot(str)
    def open(self, path):
        try:
            if self.reader is not None:
                self.reader.close()
            self.reader = CaptureReader(path)
        except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
            self.reader = None
            self.failed.emit(str(exc))
            return
        self.playing = False
        self.seek(self.reader.index[0][0] if self.reader.index else 0)

    @Slot(int)
    def seek(self, seq):
        if self.reader is None:
            return
        last = self.reader.index[-1][0] if self.reader.index else 0
        self.seq = max(0, min(seq, last))
        # Paused virtual time stops with the cursor, so freshness never ages on its own.
        self.state = self.reader.state_at(self.seq)
        self.history = {k: deque(v, maxlen=HISTORY_POINTS)
                        for k, v in self.reader.series(self.seq).items()}
        self.virtual_ns = self._t_mono(self.seq)
        self._publish()

    def _t_mono(self, seq):
        for row in self.reader.index[max(0, seq - 1):seq + 1]:
            if row[0] == seq:
                return row[1]
        return self.reader.index[0][1] if self.reader.index else 0

    def _t_unix_ms(self, seq):
        for row in self.reader.index[max(0, seq - 1):seq + 1]:
            if row[0] == seq:
                return row[2] // 1_000_000
        return None

    @Slot(float)
    def set_speed(self, speed):
        self.speed = speed

    @Slot(bool)
    def set_playing(self, playing):
        self.playing = playing and self.reader is not None
        self.last_tick = time.monotonic_ns()

    @Slot()
    def step(self):
        if self.reader is None:
            return
        self.playing = False
        last = self.reader.index[-1][0] if self.reader.index else 0
        if self.seq < last:
            self._advance_to(self.seq + 1)
            self.virtual_ns = self._t_mono(self.seq)
            self._publish()

    def _advance_to(self, seq):
        for event in self.reader.apply(self.state, self.seq, seq):
            if event['kind'] == 'sample':
                payload = event['payload']
                observed = payload.get('observed_unix_ms')
                self.history.setdefault(payload['series'], deque(maxlen=HISTORY_POINTS)).append(
                    (observed if type(observed) is int else self._t_unix_ms(seq), payload.get('value')))
        self.seq = seq

    def _tick(self):
        if not self.playing or self.reader is None:
            return
        now = time.monotonic_ns()
        self.virtual_ns += int((now - self.last_tick) * self.speed)
        self.last_tick = now
        target = self.reader.seq_at(self.virtual_ns)
        if target > self.seq:
            self._advance_to(target)
            self._publish()
        if self.reader.index and self.seq >= self.reader.index[-1][0]:
            self.playing = False
            self._publish()

    def _publish(self):
        plans, messages = self.reader.trial_messages(self.seq)
        scope_prefix = {key.split(':', 1)[0] for key in self.state.nodes}
        history = {}
        for series, points in self.history.items():
            # CaptureReader keys by bare series; the live model keys by scope:series.
            for scope in scope_prefix or {''}:
                history[f'{scope}:{series}' if scope else series] = list(points)
        t_unix = self._t_unix_ms(self.seq)
        self.snapshot.emit({'mode': 'REPLAY', 'state': public_state(self.state), 'history': history,
                            'now_unix_ms': t_unix, 'now_mono_ns': self.virtual_ns,
                            'trial_events': [{'kind': 'trial_run', 'payload': p} for p in plans.values()] +
                                            [{'kind': 'trial_message', 'payload': m} for m in messages]})
        self.position.emit({'seq': self.seq, 'first': self.reader.index[0][0] if self.reader.index else 0,
                            'last': self.reader.index[-1][0] if self.reader.index else 0,
                            't_unix_ms': t_unix, 'playing': self.playing,
                            'closed_cleanly': self.reader.closed_cleanly,
                            'path': str(self.reader.path)})

    @Slot()
    def stop(self):
        if hasattr(self, 'timer'):
            self.timer.stop()
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        _release(self)


class BoardWorker(QObject):
    """Serial probe/flash batches on a worker thread; the flash itself is a separate process."""
    progress = Signal(str, str, str)
    probed = Signal(str, object, str)
    finished = Signal(list)

    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.cancel = threading.Event()

    @Slot(list)
    def probe(self, ports):
        for port in ports:
            self.progress.emit(port, 'Inspecting', 'ROM probe 中（board は reset される）')
            try:
                self.probed.emit(port, self.backend.probe(port), '')
            except Exception as exc:
                self.probed.emit(port, None, str(exc))
        self.finished.emit([])

    @Slot(list)
    def flash(self, items):
        from ..device import run_batch
        self.cancel.clear()

        def worker(port, plan):
            # Stop is honored between boards; a board being written finishes safely.
            if self.cancel.is_set():
                raise RuntimeError('中止：未着手')
            self.progress.emit(port, 'Flashing', '書込み・verify 中')
            return self.backend.flash(port, plan)

        results = run_batch(items, worker, self.backend.leases)
        self.finished.emit([(r.port, r.ok, r.error) for r in results])


def _worker_env():
    env = dict(os.environ)
    package_root = str(Path(__file__).resolve().parents[2])
    env['PYTHONPATH'] = os.pathsep.join(filter(None, [package_root, env.get('PYTHONPATH')]))
    return env


class RealBoards:
    """pyserial enumeration; probe/flash run in the isolated esptool worker process."""
    def __init__(self):
        from ..device import PortLeases
        self.leases = PortLeases()

    def list_ports(self):
        from ..device import list_ports
        # Mesh Lab boards are USB serial devices; legacy on-board UARTs have no VID.
        return [port for port in list_ports() if port.vid is not None]

    @staticmethod
    def _run(request, timeout):
        # Fixed argv and JSON stdin: no shell string, no caller-controlled trust anchor.
        done = subprocess.run([sys.executable, '-m', 'routeloom_meshviz.flash_worker'],
                              input=json.dumps(request), capture_output=True, text=True,
                              timeout=timeout, env=_worker_env())
        lines = done.stdout.strip().splitlines()
        result = json.loads(lines[-1]) if lines else {'ok': False, 'error': done.stderr[-400:]}
        if not result.get('ok'):
            raise RuntimeError(result.get('error') or 'flash worker failed')
        return result

    def probe(self, port):
        from ..device import Identity
        return Identity(**self._run({'op': 'probe', 'port': port}, 30)['identity'])

    def flash(self, port, plan):
        from dataclasses import asdict
        self._run({'port': port, 'bundle': str(plan.bundle), 'expected': asdict(plan.expected),
                   'expected_mac': plan.expected_mac, 'quiesced': plan.quiesced}, 180)
        return True


class FakeBoards:
    """Three fake USB boards behind a fake esptool API; the real worker checks still run."""
    def __init__(self):
        from ..device import Identity, Port, PortLeases
        self.leases = PortLeases()
        self.ports = [Port('fake://A', 0x303a, 0x1001, 'FAKE-A', 'hub-1.1', None),
                      Port('fake://B', 0x303a, 0x1001, 'FAKE-B', 'hub-1.2', None),
                      Port('fake://C', 0x10c4, 0xea60, None, 'hub-1.3', None)]
        self.identities = {
            'fake://A': Identity('esp32c3', '4', 'aa:bb:cc:00:00:01', None, '164020', 4 << 20, False, False),
            'fake://B': Identity('esp32s3', '1', 'aa:bb:cc:00:00:02', None, '174020', 8 << 20, False, False),
            'fake://C': Identity('esp32c3', '4', 'aa:bb:cc:00:00:03', None, '164020', 4 << 20, False, None),
        }
        self.written = {}

    def list_ports(self):
        return list(self.ports)

    def _api(self, port):
        identity = self.identities[port]
        boards = self

        class ROM:
            CHIP_NAME = identity.chip.upper().replace('ESP32', 'ESP32-')

            def __init__(self):
                self._port = self

            def close(self):
                pass

            def read_mac(self, kind):
                return bytes.fromhex(identity.base_mac.replace(':', ''))

            def flash_id(self):
                return int(identity.flash_id, 16)

            def get_chip_revision(self):
                return int(identity.revision)

            def get_security_info(self, cache=False):
                count = {False: 0, True: 1, None: None}[identity.flash_encryption]
                return {'parsed_flags': {'SECURE_BOOT_EN': identity.secure_boot},
                        'flash_crypt_cnt': count}

        class API:
            __version__ = '5.4.0'

            @staticmethod
            def detect_chip(**kw):
                time.sleep(0.05)
                return ROM()

            @staticmethod
            def attach_flash(esp):
                pass

            @staticmethod
            def write_flash(esp, images, **kw):
                time.sleep(0.2)
                boards.written[port] = [offset for offset, _ in images]

            @staticmethod
            def verify_flash(esp, images):
                pass

        return API

    def probe(self, port):
        from ..flash_worker import probe
        return probe(port, api=self._api(port))

    def flash(self, port, plan):
        from ..flash_worker import flash
        flash(port, plan, api=self._api(port))
        return True
