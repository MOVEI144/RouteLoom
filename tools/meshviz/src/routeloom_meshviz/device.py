"""Safe write plans and port identity; USB descriptor values never prove ESP identity."""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import tempfile
import threading


@dataclass(frozen=True)
class Port:
    path: str
    vid: int | None
    pid: int | None
    serial: str | None
    location: str | None
    interface: str | None


def list_ports():
    # Import on demand: model/replay and tests do not require USB or Qt.
    from serial.tools import list_ports as serial_ports
    return [Port(p.device, p.vid, p.pid, p.serial_number, p.location, p.interface)
            for p in serial_ports.comports()]


@dataclass(frozen=True)
class Identity:
    chip: str
    revision: str
    base_mac: str
    sta_mac: str | None
    flash_id: str
    flash_bytes: int
    secure_boot: bool | None
    flash_encryption: bool | None


def reconcile(expected: Identity, ports: list[Port], probed: dict[str, Identity]):
    """Only a unique, freshly probed full identity can survive re-enumeration."""
    matches = [p.path for p in ports if probed.get(p.path) == expected]
    return matches[0] if len(matches) == 1 else None


def _port_key(port):
    if not isinstance(port, str) or not port:
        return None
    return os.path.normcase(os.path.realpath(port))


class PortLeases:
    def __init__(self):
        self.lock = threading.Lock()
        self.held = set()
        self.held_ports = set()
        self.directory = Path(tempfile.gettempdir()) / 'routeloom-port-leases'

    @contextmanager
    def acquire(self, board_uuid, port=None):
        if port is not None:
            port = _port_key(port)
            if port is None:
                raise ValueError('port is unavailable')
        with self.lock:
            if board_uuid in self.held or (port is not None and port in self.held_ports):
                raise ValueError('board or port already leased')
            self.held.add(board_uuid)
            if port is not None:
                self.held_ports.add(port)
        # Exclusive creation also fences other processes. Stale files require
        # explicit operator recovery rather than guessing that a port is free.
        opened = []
        names = [f'board:{board_uuid}']
        if port is not None:
            names.append(f'port:{port}')
        try:
            self.directory.mkdir(mode=0o700, exist_ok=True)
            for name in sorted(names):
                path = self.directory / hashlib.sha256(name.encode()).hexdigest()
                try:
                    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError as exc:
                    raise ValueError('board or port leased by another process') from exc
                opened.append((fd, path))
                os.write(fd, str(os.getpid()).encode())
            yield
        finally:
            for fd, path in reversed(opened):
                os.close(fd)
                path.unlink()
            with self.lock:
                self.held.remove(board_uuid)
                if port is not None:
                    self.held_ports.remove(port)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.held or self.held_ports:
            raise ValueError('leases still held')


@dataclass(frozen=True)
class Image:
    offset: int
    path: Path
    size: int
    sha256: str


@dataclass(frozen=True)
class FlashPlan:
    expected: Identity
    chip: str
    images: tuple[Image, ...]
    verified_signature: bool
    expected_mac: str
    quiesced: bool = False
    bundle: Path | None = None

    def verified_images(self, port: str, measured: Identity) -> list[tuple[int, bytes]]:
        if (not port or not self.quiesced or not self.verified_signature or measured != self.expected or
                self.chip != measured.chip or self.expected_mac.lower() != measured.base_mac.lower() or
                measured.secure_boot is not False or measured.flash_encryption is not False or
                type(measured.flash_bytes) is not int or measured.flash_bytes <= 0 or not self.images):
            raise ValueError('identity, signature or protection state unverified')
        end = 0
        verified = []
        for image in sorted(self.images, key=lambda i: i.offset):
            if (type(image.offset) is not int or type(image.size) is not int or
                    image.offset < end or image.offset < 0 or image.offset % 0x1000 or
                    image.size <= 0 or image.offset + image.size > measured.flash_bytes):
                raise ValueError('invalid flash offset/size or overlap')
            if not image.path.is_file() or image.path.stat().st_size != image.size:
                raise ValueError('image missing or size mismatch')
            contents = image.path.read_bytes()
            if len(contents) != image.size:
                raise ValueError('image size changed during verification')
            digest = hashlib.sha256(contents).hexdigest()
            if digest != image.sha256.lower():
                raise ValueError('image hash mismatch')
            verified.append((image.offset, contents))
            end = image.offset + image.size
        return verified

    def verify(self, port: str, measured: Identity):
        self.verified_images(port, measured)


@dataclass(frozen=True)
class Result:
    port: str | None
    ok: bool
    error: str | None = None


def run_batch(items, worker, leases=None):
    """The worker owns probe, preflight and write in one ROM session."""
    leases = leases or PortLeases()
    items = list(items)
    identities = [plan.expected.base_mac.lower() for _, plan in items]
    ports = [_port_key(port) for port, _ in items]
    results = []
    for port, plan in items:
        port_key = _port_key(port)
        if port_key is None:
            results.append(Result(port, False, 'port is unavailable'))
            continue
        if (identities.count(plan.expected.base_mac.lower()) > 1 or
                ports.count(port_key) > 1):
            # Duplicate assignments are ambiguous even if the first write succeeds.
            results.append(Result(port, False, 'duplicate board identity or port'))
            continue
        try:
            with leases.acquire(plan.expected.base_mac.lower(), port):
                if worker(port, plan) is False:
                    raise RuntimeError('worker reported failure')
            results.append(Result(port, True))
        except Exception as exc:
            results.append(Result(port, False, str(exc)))
    return results


def import_rig(path):
    """Use HIL's existing restricted YAML parser and board validation, not a copy."""
    import importlib.util
    import sys
    module_name = '_routeloom_meshviz_hil_rig'
    module = sys.modules.get(module_name)
    if module is None:
        rig_file = Path(__file__).resolve().parents[3] / 'hil' / 'rig.py'
        spec = importlib.util.spec_from_file_location(module_name, rig_file)
        if spec is None or spec.loader is None:
            raise ImportError('HIL rig parser is unavailable')
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            del sys.modules[module_name]
            raise
    return module.load_rigs(str(path))
