"""Qt-free SiteSupervisor: start or attach the site daemon, verify it, watch it, reconnect.

Runs on a worker thread; every call here may block briefly (socket probe,
process wait) and must never be called from the GUI thread. Rules
(design-devflow §3):

- one supervisor per site directory (process lock), one bridge port per site
  (PortLeases), and the daemon's own exclusive site.db lock stays in force;
- a daemon is accepted only after capabilities.get (versioned) and
  site.status answer, and its site_id matches the site this supervisor is
  bound to. Another site's socket is refused, never adopted;
- a crash or a lost daemon is re-probed and, for an owned daemon, restarted
  with bounded back-off. Recovery never creates new keys or an empty DB;
- only a daemon this supervisor started is stopped by it.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess

from .api1_adapter import LineDecoder, encode_request

PROBE_TIMEOUT_S = 2.0
START_DEADLINE_MS = 15_000
HEALTH_PERIOD_MS = 2_000
HEALTH_FAILURES = 3
RESTART_BACKOFF_MS = (1_000, 2_000, 4_000, 8_000, 16_000)
RESTART_WINDOW_MS = 600_000
STOP_WAIT_S = 5.0
LAB_INIT_TIMEOUT_S = 120
OUTPUT_TAIL = 2000


@dataclass
class SiteConfig:
    site_dir: Path
    socket: Path
    daemon: str = 'routeloom-host'
    device: str | None = None
    acl_file: Path | None = None
    expected_site_id: str | None = None


def probe_api1(path, *, timeout=PROBE_TIMEOUT_S):
    """capabilities.get + site.status over one short connection; raises OSError/ValueError."""
    if not hasattr(socket, 'AF_UNIX'):
        raise OSError('この OS の daemon IPC は未対応（D13a/b）')
    replies = {}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(path))
        conn.sendall(encode_request('sv-caps', 'capabilities.get', {}) +
                     encode_request('sv-site', 'site.status', {}))
        decoder = LineDecoder()
        while len(replies) < 2:
            chunk = conn.recv(65536)
            if not chunk:
                raise OSError('daemon closed the probe connection')
            for reply in decoder.feed(chunk):
                replies[reply['request_id']] = reply
    return replies.get('sv-caps'), replies.get('sv-site')


def verify_daemon(caps, site, bound_site_id):
    """→ (site_id, problem). A problem means the daemon must not be used for this site."""
    if not caps or not caps.get('ok'):
        return None, 'capabilities.get が失敗'
    result = caps['result']
    version = result.get('caps_version')
    api = result.get('api') if isinstance(result.get('api'), dict) else {}
    if type(version) is not int or version < 1 or api.get('version') != 1:
        return None, 'capabilities の版が不明（caps_version／api.version）'
    methods = result.get('methods') if isinstance(result.get('methods'), dict) else {}
    if methods.get('site.status') is not True:
        return None, 'daemon が site.status を広告していない（Site Authority なし）'
    if not site or not site.get('ok'):
        code = (site or {}).get('error', {}).get('code')
        return None, f'site.status が失敗（{code or "応答なし"}）'
    site_id = site['result'].get('site_id')
    if not isinstance(site_id, str) or len(site_id) != 16:
        return None, 'site.status の site_id が不正'
    if bound_site_id is not None and site_id != bound_site_id:
        return site_id, f'別 site の daemon（{site_id} ≠ {bound_site_id}）'
    return site_id, None


class SiteLock:
    """Advisory per-site-directory lock so two Mesh Labs cannot supervise one site."""
    def __init__(self, site_dir):
        self.path = Path(site_dir) / 'ipc' / 'meshlab-supervisor.lock'
        self.fd = None

    def acquire(self):
        try:
            import fcntl
        except ImportError:  # Windows: the daemon's own site.db lock still applies
            return
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise RuntimeError('この site は別の Mesh Lab が監視中') from exc
        self.fd = fd

    def release(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class SiteSupervisor:
    """State: idle → starting|attaching → ready ⇄ reconnecting → stopped | mismatch | failed."""
    def __init__(self, *, probe=probe_api1, launcher=subprocess.Popen, leases=None):
        self.probe = probe
        self.launcher = launcher
        self.leases = leases
        self.config = None
        self.owned = False
        self.process = None
        self.lock = None
        self.lease = None
        self.log = None
        self.state = 'idle'
        self.reason = None
        self.site_id = None
        self.session = 0
        self.site_status = None
        self.methods = {}
        self.caps_version = None
        self.deadline_ms = None
        self.next_probe_ms = 0
        self.failures = 0
        self.restarts = []
        self.history = []

    # --- commands ------------------------------------------------------------

    def attach(self, config, now_ms):
        """Use an existing daemon; it is never stopped or replaced by this supervisor."""
        self._begin(config, owned=False)
        self.state = 'attaching'
        self.deadline_ms = now_ms + START_DEADLINE_MS
        self.next_probe_ms = now_ms

    def start(self, config, now_ms):
        """Start routeloom-host as a child for this site directory."""
        self._begin(config, owned=True)
        try:
            self.lock = SiteLock(config.site_dir)
            self.lock.acquire()
            if config.device and self.leases is not None:
                self.lease = self.leases.acquire(f'daemon:{config.site_dir}', config.device)
                self.lease.__enter__()
        except (RuntimeError, ValueError, OSError) as exc:
            self._release()
            self._fail(f'起動前の占有に失敗: {exc}')
            return
        try:
            self.probe(config.socket)
        except (OSError, ValueError):
            pass
        else:
            self._release()
            self._fail('socket に既存の daemon が応答中（attach を選ぶ）')
            return
        self._spawn(now_ms)

    def stop(self):
        """Stop an owned daemon (terminate, then kill); an attached one is only detached."""
        if self.process is not None:
            self.state = 'stopping'
            self.process.terminate()
            try:
                self.process.wait(timeout=STOP_WAIT_S)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=STOP_WAIT_S)
            self._note(f'所有 daemon を停止（exit {self.process.returncode}）')
            self.process = None
        elif self.state not in ('idle', 'stopped'):
            self._note('attach を解除（daemon は停止しない）')
        self._release()
        self.state = 'stopped'
        self.methods = {}
        self.site_status = None

    # --- periodic ------------------------------------------------------------

    def tick(self, now_ms):
        if self.state in ('idle', 'stopped', 'mismatch', 'failed', 'stopping'):
            return
        if self.process is not None and self.process.poll() is not None:
            code = self.process.returncode
            self.process = None
            self._lost(f'所有 daemon が終了（exit {code}）', now_ms, restart=True)
            return
        if self.process is None and self.owned and self.state == 'reconnecting':
            if now_ms >= self.next_probe_ms:
                self._spawn(now_ms)
            return
        if now_ms < self.next_probe_ms:
            return
        self.next_probe_ms = now_ms + (500 if self.state != 'ready' else HEALTH_PERIOD_MS)
        try:
            caps, site = self.probe(self.config.socket)
        except (OSError, ValueError) as exc:
            self._probe_failed(str(exc), now_ms)
            return
        site_id, problem = verify_daemon(caps, site, self.site_id)
        if problem is not None:
            if site_id is not None and self.site_id is not None and site_id != self.site_id:
                # Another site's daemon on our socket path: refuse, never re-bind.
                self._note(problem)
                self.state = 'mismatch'
                self.reason = problem
                if self.process is not None:
                    self.stop()
                    self.state = 'mismatch'
                else:
                    self._release()
                self.methods = {}
                return
            self._probe_failed(problem, now_ms)
            return
        if self.site_id is None:
            self.site_id = site_id
        self.failures = 0
        self.site_status = site['result']
        methods = caps['result'].get('methods') or {}
        self.methods = {key: value is True for key, value in methods.items()}
        self.caps_version = caps['result'].get('caps_version')
        if self.state != 'ready':
            # A new session: the GUI must re-read capabilities, snapshots and
            # reconcile its operations before trusting earlier state.
            self.session += 1
            self.state = 'ready'
            self.reason = None
            self._note(f'daemon 接続（session {self.session}、site {site_id}）')

    # --- internals -------------------------------------------------------------

    def _begin(self, config, *, owned):
        if self.state not in ('idle', 'stopped', 'mismatch', 'failed'):
            self.stop()
        self.config = config
        self.owned = owned
        self.site_id = config.expected_site_id
        self.reason = None
        self.failures = 0
        self.restarts = []
        self.methods = {}
        self.site_status = None

    def _argv(self):
        config = self.config
        argv = [config.daemon, '--socket', str(config.socket), '--site-authority', str(config.site_dir)]
        if config.device:
            argv += ['--device', config.device]
        if config.acl_file:
            argv += ['--api-acl-file', str(config.acl_file)]
        return argv

    def _spawn(self, now_ms):
        log_path = Path(self.config.site_dir) / 'ipc' / 'daemon.log'
        try:
            log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.log is None:
                fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
                self.log = os.fdopen(fd, 'ab')
            # Fixed argv, no shell; the daemon reads its keys from the site directory.
            self.process = self.launcher(self._argv(), stdin=subprocess.DEVNULL,
                                         stdout=self.log, stderr=self.log)
        except OSError as exc:
            self._release()
            self._fail(f'daemon を起動できない: {exc}')
            return
        self.state = 'starting'
        self.deadline_ms = now_ms + START_DEADLINE_MS
        self.next_probe_ms = now_ms + 300
        self._note(f'daemon 起動（pid {getattr(self.process, "pid", "?")}）')

    def _probe_failed(self, reason, now_ms):
        self.reason = reason
        if self.state in ('starting', 'attaching'):
            if now_ms >= self.deadline_ms:
                if self.process is not None:
                    self.stop()
                self._release()
                self._fail(f'起動確認に失敗: {reason}')
            return
        self.failures += 1
        if self.state == 'ready' and self.failures >= HEALTH_FAILURES:
            self._lost(f'応答なし: {reason}', now_ms, restart=False)

    def _lost(self, reason, now_ms, *, restart):
        self._note(reason)
        self.reason = reason
        self.methods = {}
        self.site_status = None
        self.state = 'reconnecting'
        if restart and self.owned:
            self.restarts = [t for t in self.restarts if now_ms - t < RESTART_WINDOW_MS]
            if len(self.restarts) >= len(RESTART_BACKOFF_MS):
                self._release()
                self._fail(f'再起動上限に到達: {reason}')
                return
            self.next_probe_ms = now_ms + RESTART_BACKOFF_MS[len(self.restarts)]
            self.restarts.append(now_ms)
        else:
            self.next_probe_ms = now_ms + RESTART_BACKOFF_MS[0]

    def _fail(self, reason):
        self._note(reason)
        self.state = 'failed'
        self.reason = reason
        self.methods = {}

    def _release(self):
        if self.lease is not None:
            self.lease.__exit__(None, None, None)
            self.lease = None
        if self.lock is not None:
            self.lock.release()
            self.lock = None
        if self.log is not None and self.process is None:
            self.log.close()
            self.log = None

    def _note(self, text):
        self.history.append(text)
        del self.history[:-32]

    def snapshot(self):
        status = self.site_status or {}
        usb = status.get('usb') if isinstance(status.get('usb'), dict) else {}
        authority = status.get('authority') if isinstance(status.get('authority'), dict) else {}
        return {'state': self.state, 'reason': self.reason, 'owned': self.owned,
                'session': self.session, 'site_id': self.site_id,
                'socket': str(self.config.socket) if self.config else None,
                'site_dir': str(self.config.site_dir) if self.config else None,
                'caps_version': self.caps_version, 'methods': dict(self.methods),
                'usb': dict(usb), 'authority': dict(authority),
                'site_status': dict(status), 'history': list(self.history)}


def lab_site_init(ctl, spec_path, out_dir, *, run=subprocess.run):
    """`routeloomctl lab-site-init --spec FILE --out DIR`; 未対応 when the CLI predates it.

    The CLI owns key generation, private permissions and resuming a partial
    site; this wrapper never creates keys, retries with a fresh CA, or passes
    secrets through argv.
    """
    try:
        done = run([ctl, 'lab-site-init', '--spec', str(spec_path), '--out', str(out_dir)],
                   capture_output=True, text=True, timeout=LAB_INIT_TIMEOUT_S)
    except FileNotFoundError:
        return {'state': 'unsupported', 'detail': f'{ctl} が見つからない'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'state': 'failed', 'detail': str(exc)}
    output = (done.stdout or '')[-OUTPUT_TAIL:]
    error = (done.stderr or '')[-OUTPUT_TAIL:]
    if done.returncode != 0:
        if 'invalid command' in error or 'unknown command' in error:
            return {'state': 'unsupported',
                    'detail': 'routeloomctl に lab-site-init が無い（古い CLI）'}
        return {'state': 'failed', 'detail': error or output}
    return {'state': 'created', 'detail': output}


def _random_id(bits):
    """Non-reserved random id (not 0, not all ones) from the OS CSPRNG."""
    while True:
        value = secrets.randbits(bits)
        if 0 < value < (1 << bits) - 1:
            return f'{value:0{bits // 4}x}'


def write_lab_spec(path, *, gateway, channel):
    """routeloom-lab-site-spec-v1 for lab-site-init; an existing spec is reused unchanged.

    Reusing the file keeps the site/CA/SAK ids of a partially created site, so
    a retry resumes that site instead of making a new one.
    """
    path = Path(path)
    if path.exists():
        return path
    if type(channel) is not int or not 1 <= channel <= 14:
        raise ValueError('channel は 1..14')
    if (not isinstance(gateway, str) or len(gateway) != 16 or
            any(c not in '0123456789abcdef' for c in gateway) or
            int(gateway, 16) in (0, (1 << 64) - 1)):
        raise ValueError('gateway（bridge）NodeId は 16 桁の hex')
    spec = {'format': 'routeloom-lab-site-spec-v1', 'site_id': _random_id(64),
            'device_ca_id': _random_id(64), 'site_ca_id': _random_id(64),
            'network_low32': _random_id(32), 'channel': channel, 'gateways': [gateway]}
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(spec, stream)
    return path


def write_self_acl(site_dir, network_low32):
    """ACL for a site this Mesh Lab just created: the current user only, this network only.

    Only new lab sites get it; an existing site's grants are never widened here.
    """
    if not hasattr(os, 'getuid'):
        raise OSError('この OS の ACL 生成は未対応（D13b）')
    network = int(network_low32, 16)
    if not 1 <= network <= 0xFFFF_FFFF:
        raise ValueError('network_low32 が不正')
    path = Path(site_dir) / 'ipc' / 'api-acl.json'
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    grants = {'principals': {str(os.getuid()): {'networks': {f'{network:016x}': [
        'MEMBERSHIP_READ', 'MEMBERSHIP_DECIDE', 'MEMBERSHIP_ADMIN']}}}}
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(grants, stream)
    return path
