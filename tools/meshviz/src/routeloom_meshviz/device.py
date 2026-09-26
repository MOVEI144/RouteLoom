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
    sta_mac: str
    flash_id: str
    flash_bytes: int
    secure_boot: bool | None
    flash_encryption: bool | None


def reconcile(expected: Identity, ports: list[Port], probed: dict[str, Identity]):
    """Only a unique, freshly probed full identity can survive re-enumeration."""
    matches = [p.path for p in ports if probed.get(p.path) == expected]
    return matches[0] if len(matches) == 1 else None


class PortLeases:
    def __init__(self):
        self.lock = threading.Lock()
        self.held = set()
        self.directory = Path(tempfile.gettempdir()) / 'routeloom-port-leases'

    @contextmanager
    def acquire(self, board_uuid):
        with self.lock:
            if board_uuid in self.held:
                raise ValueError('board already leased')
            self.held.add(board_uuid)
        # Exclusive creation also fences other processes. Stale files require
        # explicit operator recovery rather than guessing that a port is free.
        fd = None
        path = self.directory / hashlib.sha256(board_uuid.encode()).hexdigest()
        try:
            self.directory.mkdir(mode=0o700, exist_ok=True)
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise ValueError('board leased by another process') from exc
            os.write(fd, str(os.getpid()).encode())
            yield
        finally:
            if fd is not None:
                os.close(fd)
                path.unlink()
            with self.lock:
                self.held.remove(board_uuid)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.held:
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

    def verify(self, port: str, measured: Identity):
        if (not port or not self.quiesced or not self.verified_signature or measured != self.expected or
                self.chip != measured.chip or self.expected_mac.lower() != measured.base_mac.lower() or
                measured.secure_boot is not False or measured.flash_encryption is not False or
                measured.flash_bytes <= 0 or not self.images):
            raise ValueError('identity, signature or protection state unverified')
        end = 0
        for image in sorted(self.images, key=lambda i: i.offset):
            if image.offset < end or image.offset < 0 or image.offset % 0x1000 or image.size <= 0 or image.offset + image.size > measured.flash_bytes:
                raise ValueError('invalid flash offset/size or overlap')
            if not image.path.is_file() or image.path.stat().st_size != image.size:
                raise ValueError('image missing or size mismatch')
            digest = hashlib.sha256(image.path.read_bytes()).hexdigest()
            if digest != image.sha256.lower():
                raise ValueError('image hash mismatch')
            end = image.offset + image.size


@dataclass(frozen=True)
class Result:
    port: str
    ok: bool
    error: str | None = None


def run_batch(items, worker, leases=None):
    """The worker owns probe, preflight and write in one ROM session."""
    leases = leases or PortLeases()
    items = list(items)
    identities = [plan.expected.base_mac.lower() for _, plan in items]
    ports = [port for port, _ in items]
    results = []
    for port, plan in items:
        if identities.count(plan.expected.base_mac.lower()) > 1 or ports.count(port) > 1:
            # Duplicate assignments are ambiguous even if the first write succeeds.
            results.append(Result(port, False, 'duplicate board identity or port'))
            continue
        try:
            with leases.acquire(plan.expected.base_mac):
                worker(port, plan)
            results.append(Result(port, True))
        except (ValueError, OSError, TimeoutError) as exc:
            results.append(Result(port, False, str(exc)))
    return results


def import_rig(path):
    """Use HIL's existing restricted YAML parser and board validation, not a copy."""
    import sys
    hil_dir = str(Path(path).resolve().parent)
    if hil_dir not in sys.path:
        sys.path.insert(0, hil_dir)
    from rig import load_rigs
    return load_rigs(str(path))
