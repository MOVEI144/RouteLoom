"""Qt-free per-board provisioning orchestration for development sites.

Implements the development provision flow of the dev-flow design: drive the
device maintenance console over a line transport while the office tooling
(a ``routeloomctl`` subprocess driver) does the privileged signing, and keep a
durable journal so a USB disconnect or a lost response resumes from the last
committed fact instead of re-issuing or re-sealing blindly.

Boundaries this module keeps:

- The device keypair is generated on the board (``keygen``); only the PoP and
  the sealed public identity ever cross the wire. Private key material is
  never exported, journaled, or requested.
- A device that already answers ``identity=sealed`` for an identity this
  journal did not issue is refused with ``already_provisioned`` — the
  orchestrator never auto-wipes.
- ``Ready`` is only declared after the post-field readback matches the office
  expectation sheet (``finalize``); a sealed identity alone is not readiness.
- Deprovision is a separate journaled work item with explicit target binding;
  an unreadable store requires ``wipe_unverifiable`` so a casual caller cannot
  wipe an unchecked board.
"""
from __future__ import annotations

from .provision_plan import (LAB_ROLES, STEP_NAMES, ContractBackend, FakeProvisionBackend,
                             ProvisionRunner, StepResult, auto_approval_text,
                             inventory_rows, job_status_text, plan_jobs,
                             valid_lab_node_id)

import hashlib
import json
import os
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

JOURNAL_FORMAT = 'routeloom-provision-journal-v1'

# sdkv1_maintenance.hpp: the `identity` line carries the bundle as hex inside
# kMaintenanceBundleMax decoded bytes.
BUNDLE_BYTES_MAX = 2048

_HEX16 = re.compile(r'^[0-9a-f]{16}$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_HEX_EVEN = re.compile(r'^(?:[0-9a-f]{2})+$')

# Console replies the orchestrator treats as a hard stop: the device state does
# not match the work item and operator action is required (no silent retry).
_REASONS_FATAL = {
    'already_provisioned',
    'identity_committed',
    'node_mismatch',
    'key_mismatch',
    'locked',
}


class ProvisionError(Exception):
    """A refused or failed provisioning step; ``reason`` is a stable token."""

    def __init__(self, reason: str, detail: str = ''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason
        self.detail = detail


def _require_hex16(text, what):
    if not isinstance(text, str) or not _HEX16.match(text):
        raise ProvisionError('bad_plan', f'{what} must be 16 lowercase hex digits')
    return text


def _require_hex64(text, what):
    if not isinstance(text, str) or not _HEX64.match(text):
        raise ProvisionError('bad_plan', f'{what} must be 64 lowercase hex digits')
    return text


@dataclass(frozen=True)
class BoardProvisionPlan:
    """One board's provisioning work item.

    ``base_mac`` is the freshly probed ROM base/STA MAC of the board on the
    leased port — the journal binds it so the same port cannot silently switch
    boards between stages. ``out_dir`` is the office output directory; the
    office work_id defaults to its basename and must equal ``work_id`` here.
    """

    site_id: str
    work_id: str
    board_uuid: str
    base_mac: str
    node_id: str
    serial: int
    role: str
    out_dir: str
    fw: str = ''
    field_digest: str = ''

    def as_dict(self):
        return {
            'site_id': self.site_id,
            'work_id': self.work_id,
            'board_uuid': self.board_uuid,
            'base_mac': self.base_mac,
            'node_id': self.node_id,
            'serial': self.serial,
            'role': self.role,
            'out_dir': self.out_dir,
            'fw': self.fw,
            'field_digest': self.field_digest,
        }

    def validate(self):
        _require_hex16(self.site_id, 'site_id')
        _require_hex16(self.node_id, 'node_id')
        if not self.work_id or '/' in self.work_id or self.work_id.startswith('.'):
            raise ProvisionError('bad_plan', 'work_id must be a plain file-stem')
        if int(self.node_id, 16) in (0, 2**64 - 1):
            raise ProvisionError('bad_plan', 'node_id is a reserved value')
        if not isinstance(self.serial, int) or self.serial < 0 or self.serial > 0xFFFFFFFF:
            raise ProvisionError('bad_plan', 'serial must be a u32')
        if not self.role:
            raise ProvisionError('bad_plan', 'role is required')
        if self.field_digest and not _HEX64.match(self.field_digest):
            raise ProvisionError('bad_plan', 'field_digest must be sha256 hex')
        if self.fw and len(self.fw) > 32:
            raise ProvisionError('bad_plan', 'fw must fit the console receipt')
        return self


@dataclass(frozen=True)
class DeprovisionPlan:
    """Explicit deprovision work item — always opt-in, always target-bound."""

    work_id: str
    expected_node_id: str
    expected_kid: str = ''
    base_mac: str = ''
    wipe_unverifiable: bool = False

    def validate(self):
        if not self.work_id or '/' in self.work_id or self.work_id.startswith('.'):
            raise ProvisionError('bad_plan', 'work_id must be a plain file-stem')
        if self.expected_node_id:
            _require_hex16(self.expected_node_id, 'expected_node_id')
        if self.expected_kid:
            _require_hex64(self.expected_kid, 'expected_kid')
        if not self.wipe_unverifiable and not self.expected_node_id:
            raise ProvisionError(
                'bad_plan', 'deprovision needs an expected node, or wipe_unverifiable'
            )
        return self


class MaintenanceLink(Protocol):
    """One request → one reply line against the device maintenance console."""

    def exchange(self, line: str) -> str: ...


class SerialMaintenanceLink:
    """USB-serial line transport for the device maintenance console.

    Reads until the console's `OK `/`ERR ` reply, skipping banner and echo
    lines; a deadline keeps a wedged board from blocking the orchestrator.
    ``serial`` is imported lazily so headless validation stays Qt/pyserial-free.
    """

    def __init__(self, port: str, *, baudrate: int = 115200, timeout_s: float = 5.0):
        import serial  # pyserial

        self._ser = serial.Serial(port, baudrate=baudrate, timeout=0.1)
        self._timeout_s = timeout_s

    def close(self):
        self._ser.close()

    def reset(self, settle_s: float = 1.0):
        """Hard-reset the board (EN via RTS) and drop the boot banner bytes.

        The ROM writer leaves the chip in the download stub; every image the
        flash worker wrote only boots after this reset.
        """
        self._ser.dtr = False
        self._ser.rts = True
        time.sleep(0.1)
        self._ser.rts = False
        time.sleep(settle_s)
        self._ser.reset_input_buffer()

    def exchange(self, line: str) -> str:
        self._ser.reset_input_buffer()
        self._ser.write(line.encode('ascii') + b'\n')
        self._ser.flush()
        deadline = time.monotonic() + self._timeout_s
        buf = b''
        while time.monotonic() < deadline:
            chunk = self._ser.read(256)
            if chunk:
                buf += chunk
                while b'\n' in buf:
                    raw, buf = buf.split(b'\n', 1)
                    reply = raw.strip().decode('ascii', 'replace')
                    if reply.startswith('OK ') or reply.startswith('ERR '):
                        return reply
        raise ProvisionError('timeout', f'no console reply within {self._timeout_s:.0f}s')


@dataclass(frozen=True)
class DeviceStatus:
    """Parsed `status` console receipt (sdkv1_maintenance.cpp)."""

    identity: str  # 'none' | 'sealed'
    pending: bool
    locked: bool
    node: str = ''
    kid: str = ''
    serial: int = -1
    devcert_sha256: str = ''
    fw: str = ''

    @staticmethod
    def parse(reply: str):
        if reply.startswith('ERR '):
            raise ProvisionError(reply.split()[1], reply[4:])
        if not reply.startswith('OK '):
            raise ProvisionError('bad_reply', reply[:64])
        fields = {}
        for token in reply.split():
            key, sep, value = token.partition('=')
            if sep:
                fields[key] = value
        if fields.get('identity') not in ('none', 'sealed'):
            raise ProvisionError('bad_reply', reply[:64])
        serial = -1
        if 'serial' in fields:
            try:
                serial = int(fields['serial'], 10)
            except ValueError as exc:
                raise ProvisionError('bad_reply', reply[:64]) from exc
        return DeviceStatus(
            identity=fields['identity'],
            pending=fields.get('pending') == '1',
            locked=fields.get('locked') == '1',
            node=fields.get('node', ''),
            kid=fields.get('kid', ''),
            serial=serial,
            devcert_sha256=fields.get('devcert_sha256', ''),
            fw=fields.get('fw', ''),
        )


@dataclass(frozen=True)
class Issued:
    """What the office published for this work item."""

    kid: str
    devcert_sha256: str
    out_dir: str


class OfficeDriver(Protocol):
    """Privileged office steps; the real driver shells out to routeloomctl."""

    def pop_challenge(self, node_id: str) -> str: ...

    def issue_devcert(self, plan: BoardProvisionPlan, challenge_hex: str, pop_hex: str) -> Issued: ...

    def bundle_hex(self, out_dir: str) -> str: ...

    def confirm_written(self, node_id: str, devcert_sha256: str, out_dir: str) -> None: ...

    def import_inventory(self, site_dir: str, node_id: str, role: str) -> str: ...


def _run_ctl(ctl: str, args: list) -> str:
    proc = subprocess.run(
        [ctl, *args], capture_output=True, text=True, timeout=60, check=False
    )
    if proc.returncode != 0:
        raise ProvisionError(
            'office_failed', f'{shlex.join(args)}: {proc.stderr.strip()[:200]}'
        )
    return proc.stdout


class CtlOffice:
    """Office driver over the `routeloomctl provision-*` command family.

    Only public material and digests appear on argv; the pop object is passed
    through a private temp file and the CA key stays on the office side.
    """

    def __init__(self, ctl: str, ca_key: str, spec: str, ledger: str):
        self._ctl = ctl
        self._ca_key = ca_key
        self._spec = spec
        self._ledger = ledger

    def pop_challenge(self, node_id: str) -> str:
        out = _run_ctl(self._ctl, ['provision-pop-challenge', '--node', node_id])
        return json.loads(out)['challenge_hex']

    def issue_devcert(self, plan: BoardProvisionPlan, challenge_hex: str, pop_hex: str) -> Issued:
        with tempfile.NamedTemporaryFile('w', suffix='.pop', delete=False) as tmp:
            tmp.write(pop_hex + '\n')
            tmp_path = tmp.name
        os.chmod(tmp_path, 0o600)
        try:
            _run_ctl(
                self._ctl,
                [
                    'provision-devcert',
                    '--ca-key', self._ca_key,
                    '--spec', self._spec,
                    '--node', plan.node_id,
                    '--serial', str(plan.serial),
                    '--challenge', challenge_hex,
                    '--pop', tmp_path,
                    '--out-dir', plan.out_dir,
                    '--ledger', self._ledger,
                    '--work-id', plan.work_id,
                ],
            )
        finally:
            os.unlink(tmp_path)
        record = json.loads((Path(plan.out_dir) / 'inventory.json').read_text(encoding='utf-8'))
        return Issued(kid=record['kid'], devcert_sha256=self._devcert_sha(plan), out_dir=plan.out_dir)

    def _devcert_sha(self, plan: BoardProvisionPlan) -> str:
        import hashlib

        return hashlib.sha256((Path(plan.out_dir) / 'devcert.cwt').read_bytes()).hexdigest()

    def bundle_hex(self, out_dir: str) -> str:
        text = (Path(out_dir) / 'identity-bundle.json').read_text(encoding='utf-8')
        if len(text.encode('utf-8')) > BUNDLE_BYTES_MAX:
            raise ProvisionError(
                'bundle_too_large', f'{len(text.encode())} bytes > {BUNDLE_BYTES_MAX}'
            )
        return text.encode('utf-8').hex()

    def confirm_written(self, node_id: str, devcert_sha256: str, out_dir: str) -> None:
        _run_ctl(
            self._ctl,
            [
                'provision-confirm-written',
                '--ledger', self._ledger,
                '--node', node_id,
                '--devcert-sha256', devcert_sha256,
                '--out-dir', out_dir,
            ],
        )

    def import_inventory(self, site_dir: str, node_id: str, role: str) -> str:
        """`lab-inventory-import` — the inventory step; requires a Written ledger entry."""
        return _run_ctl(
            self._ctl,
            [
                'lab-inventory-import',
                '--site', site_dir,
                '--ledger', self._ledger,
                '--node', node_id,
                '--role', role,
            ],
        )


class ProvisionJournal:
    """Append-only stage log, rewritten atomically after every entry.

    The journal is the resume contract: each stage records the evidence the
    next run re-verifies against the device/office, so replaying a completed
    stage is a consistency check rather than a blind skip. Secrets are never
    stored — the PoP object and challenge are public proof artifacts, the
    device key never leaves the board.
    """

    def __init__(self, path: Path, doc: dict):
        self.path = Path(path)
        self._doc = doc

    @classmethod
    def create(cls, journal_dir: Path, work_id: str, plan: dict) -> 'ProvisionJournal':
        journal_dir = Path(journal_dir)
        journal_dir.mkdir(parents=True, exist_ok=True)
        path = journal_dir / f'{work_id}.journal.json'
        if path.exists():
            journal = cls.load(path)
            if journal._doc['plan'] != plan:
                raise ProvisionError(
                    'plan_mismatch',
                    'journal belongs to a different work item; refusing to mix evidence',
                )
            return journal
        doc = {
            'format': JOURNAL_FORMAT,
            'created_wall': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'plan': plan,
            'stages': [],
            'done': False,
        }
        journal = cls(path, doc)
        journal._write()
        return journal

    @classmethod
    def load(cls, path: Path) -> 'ProvisionJournal':
        path = Path(path)
        doc = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(doc, dict) or doc.get('format') != JOURNAL_FORMAT:
            raise ProvisionError('bad_journal', str(path))
        if not isinstance(doc.get('plan'), dict) or not isinstance(doc.get('stages'), list):
            raise ProvisionError('bad_journal', str(path))
        return cls(path, doc)

    def _write(self):
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(
            json.dumps(self._doc, indent=2, sort_keys=True) + '\n', encoding='utf-8'
        )
        fd = os.open(tmp, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        dir_fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def record(self, stage: str, **evidence):
        entry = {
            'stage': stage,
            'mono_ms': int(time.monotonic() * 1000),
            'wall': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            **evidence,
        }
        self._doc['stages'].append(entry)
        self._write()
        return entry

    def mark_done(self):
        self._doc['done'] = True
        self._write()

    @property
    def done(self) -> bool:
        return bool(self._doc.get('done'))

    @property
    def plan(self) -> dict:
        return self._doc['plan']

    def latest(self, stage: str):
        """Latest live entry for `stage`; a `<stage>_stale` marker hides it."""
        for entry in reversed(self._doc['stages']):
            if entry['stage'] == f'{stage}_stale':
                return None
            if entry['stage'] == stage:
                return entry
        return None

    def has(self, stage: str) -> bool:
        return self.latest(stage) is not None

    def invalidate(self, stage: str, reason: str):
        """Mark the latest stage's evidence stale (device state regressed)."""
        self.record(f'{stage}_stale', reason=reason)


def _console(link: MaintenanceLink, line: str) -> str:
    """Send one console line; map ERR replies onto ProvisionError."""
    reply = link.exchange(line)
    if reply.startswith('ERR '):
        raise ProvisionError(reply.split()[1], reply[4:])
    if not reply.startswith('OK '):
        raise ProvisionError('bad_reply', reply[:64])
    return reply


def _reply_kv(reply: str) -> dict:
    out = {}
    for token in reply.split():
        key, sep, value = token.partition('=')
        if sep:
            out[key] = value
    return out


def _normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace(':', '').replace('-', '')


# --- BoardConfig (RLC1) over the setup console -------------------------------
#
# sdkv1_board_setup.hpp: the staged document is a fixed 42-byte big-endian
# record — magic "RLC1", version 1, len, node, sta_mac, chip, role, security,
# channel, network, 8 reserved bytes, crc32 over [0,38). The generation is the
# commit argument, never part of the document.
RLC1_DOC_BYTES = 42
RLC1_MAGIC = 0x524C4331  # "RLC1"
BOARD_CHIP = {'esp32c3': 1, 'esp32s3': 2, 'esp32c5': 3, 'esp32c6': 4}
BOARD_ROLE = {'bridge': 1, 'bench': 2}  # BoardRole::Bridge / ::Reference
BOARD_SECURITY = {'dev-ram': 1, 'member-edhoc': 2}  # BoardSecurity
# PT-4M-v2 image offsets of a field bundle (firmware_catalog): the app
# descriptor sits at ota_0, and an app-only write also blanks otadata so the
# bootloader boots ota_0.
APP_IMAGE_OFFSET = 0x40000
APP_ONLY_OFFSETS = frozenset((0x10000, APP_IMAGE_OFFSET))


def rlc1_document(*, node_id: str, sta_mac: str, chip: str, role: str,
                  security: str, channel: int, network: str) -> bytes:
    """Encode the RLC1 board document for `benchcfg stage <hex>`."""
    node = int(node_id, 16)
    mac = bytes.fromhex(_normalize_mac(sta_mac))
    if len(mac) != 6:
        raise ProvisionError('bad_plan', f'sta_mac {sta_mac!r} is not 6 bytes')
    if chip not in BOARD_CHIP or role not in BOARD_ROLE or security not in BOARD_SECURITY:
        raise ProvisionError('bad_plan', 'unknown chip/role/security')
    if not 1 <= channel <= 14:
        raise ProvisionError('bad_plan', 'channel must be 1..14')
    net = int(network, 16)
    body = struct.pack('>IBBH', RLC1_MAGIC, 1, 0, RLC1_DOC_BYTES)
    body += node.to_bytes(8, 'big') + mac
    body += bytes((BOARD_CHIP[chip], BOARD_ROLE[role], BOARD_SECURITY[security],
                   channel))
    body += net.to_bytes(4, 'big') + b'\0' * 8
    return body + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, 'big')


def board_config_commit(link: MaintenanceLink, document: bytes, *,
                        generation: int = 1,
                        psk_hex: str | None = None,
                        usb_secret: str | None = None) -> dict:
    """Stage secrets, stage+validate+commit the RLC1 document, then read back.

    Returns the evidence dict the caller journals; raises ProvisionError on
    any refusal. A benchcfg status mismatch after commit is a hard failure —
    never silently retried (the store re-read happens on the device).
    """
    if len(document) != RLC1_DOC_BYTES:
        raise ProvisionError('bad_plan', 'RLC1 document must be 42 bytes')
    if not 0 < generation <= 0xFFFFFFFF:
        raise ProvisionError('bad_plan', 'generation must be a nonzero u32')
    staged_secret = False
    if psk_hex is not None:
        if len(bytes.fromhex(psk_hex)) != 32:
            raise ProvisionError('bad_plan', 'psk must be 32 bytes (64 hex)')
        _console(link, f'benchsecret stage psk {generation} {psk_hex}')
        staged_secret = True
    if usb_secret is not None:
        if not usb_secret or len(usb_secret) > 63 or \
                any(c < '!' or c > '~' for c in usb_secret):
            raise ProvisionError('bad_plan', 'usb secret must be 1..63 printable ASCII')
        usb_hex = usb_secret.encode('ascii').hex()
        _console(link, f'benchsecret stage usb {generation} {usb_hex}')
        staged_secret = True
    reply = _console(link, f'benchcfg stage {document.hex()}')
    if _reply_kv(reply).get('bytes') != str(len(document)):
        raise ProvisionError('bad_reply', reply[:64])
    want_node = f'{int.from_bytes(document[8:16], "big"):016x}'
    valid = _console(link, 'benchcfg validate')
    if _reply_kv(valid).get('node') != want_node:
        raise ProvisionError('bad_reply', valid[:64])
    committed = _console(link, f'benchcfg commit {generation}')
    fields = _reply_kv(committed)
    if (fields.get('generation') != str(generation) or
            fields.get('node') != want_node):
        raise ProvisionError('commit_failed', committed[:64])
    # Read-only readback: the durable record, not the staged RAM copy.
    status = _reply_kv(_console(link, 'benchcfg status'))
    want_role = 'bridge' if document[23] == 1 else 'reference'
    want_security = 'devram' if document[24] == 1 else 'member'
    if status.get('board') != 'committed' or \
            status.get('node') != want_node or \
            status.get('generation') != str(generation) or \
            status.get('role') != want_role or \
            status.get('security') != want_security:
        raise ProvisionError('commit_failed', f'benchcfg status readback failed: '
                                              f'{status.get("board")}')
    secrets = _reply_kv(_console(link, 'benchsecret status'))
    if staged_secret:
        if secrets.get('secrets') != 'committed' or \
                secrets.get('generation') != str(generation):
            raise ProvisionError('commit_failed', 'benchsecret status readback failed')
        if psk_hex is not None and secrets.get('psk') != '1':
            raise ProvisionError('commit_failed', 'psk not committed')
        if usb_secret is not None and secrets.get('usb') != '1':
            raise ProvisionError('commit_failed', 'usb secret not committed')
        if secrets.get('fingerprint', '') != status.get('fingerprint', '') or \
                status.get('secrets_generation') != str(generation):
            raise ProvisionError(
                'commit_failed', 'config/secrets binding readback failed')
    return {'generation': generation, 'node': status.get('node', ''),
            'role': status.get('role', ''), 'security': status.get('security', ''),
            'secrets_generation': status.get('secrets_generation', '0'),
            'fingerprint': status.get('fingerprint', ''),
            'secrets_fingerprint': secrets.get('fingerprint', '')}


# --- Field-boot readback ------------------------------------------------------
#
# A field build has no console, so the boot log lines are the evidence the
# office matches against the plan (07 §6 shipping markers):
#   "sdkv1 identity: node=<dec> kid=<64hex> devcert_sha256=<64hex> ..."
#   "routeloom field boot: fw=<version> app_sha256=<64hex>"
#   "board config: gen=<n> node=0x<hex> ... secrets_gen=<n> mac=<12hex>"

@dataclass(frozen=True)
class FieldBoot:
    """Parsed field-boot log evidence; absent markers stay None/False."""

    identity: str | None = None       # 'sealed' | 'none'
    node: str | None = None           # 16-hex, from the identity line
    kid: str | None = None
    devcert_sha256: str | None = None
    fw: str | None = None
    app_sha256: str | None = None
    config_node: str | None = None    # 16-hex, from the board config line
    config_generation: int | None = None
    secrets_generation: int | None = None
    config_mac: str | None = None
    config_required: bool = False


_BOOT_IDENTITY = re.compile(
    r'sdkv1 identity: (?:node=(\d+) kid=([0-9a-f]{64}) '
    r'devcert_sha256=([0-9a-f]{64})|(none) provisioned)')
_BOOT_FIELD = re.compile(r'routeloom field boot: fw=(\S+)(?: app_sha256=([0-9a-f]{64}))?')
_BOOT_CONFIG = re.compile(
    r'board config: gen=(\d+) node=0x([0-9a-f]+)(?: \w+=\w+)* '
    r'secrets_gen=(\d+) mac=([0-9a-f]{12})')


def parse_field_boot(lines) -> FieldBoot:
    """Extract the D03 readback fields from captured boot-log lines."""
    identity = node = kid = devcert = fw = app_sha = None
    config_node = config_mac = None
    config_gen = secrets_gen = None
    required = False
    for line in lines:
        match = _BOOT_IDENTITY.search(line)
        if match:
            if match.group(4):
                identity = 'none'
            else:
                identity = 'sealed'
                node = f'{int(match.group(1)):016x}'
                kid, devcert = match.group(2), match.group(3)
            continue
        match = _BOOT_FIELD.search(line)
        if match:
            fw, app_sha = match.group(1), match.group(2)
            continue
        match = _BOOT_CONFIG.search(line)
        if match:
            config_gen = int(match.group(1))
            config_node = f'{int(match.group(2), 16):016x}'
            secrets_gen = int(match.group(3))
            config_mac = match.group(4)
            continue
        if 'CONFIG_REQUIRED' in line:
            required = True
    return FieldBoot(identity=identity, node=node, kid=kid,
                     devcert_sha256=devcert, fw=fw, app_sha256=app_sha,
                     config_node=config_node, config_generation=config_gen,
                     secrets_generation=secrets_gen, config_mac=config_mac,
                     config_required=required)


# esp_app_desc_t inside the application image: magic at offset 32, then
# version[48:80), project_name[80:112), app_elf_sha256[176:208) (v6.0.3).
_APP_DESC_MAGIC = b'\x32\x54\xcd\xab'
_APP_DESC_OFFSET = 32


def app_image_descriptor(path) -> dict:
    """version/project_name/app_elf_sha256 read from a signed app .bin."""
    data = Path(path).read_bytes()
    if (len(data) < _APP_DESC_OFFSET + 208 or
            data[_APP_DESC_OFFSET:_APP_DESC_OFFSET + 4] != _APP_DESC_MAGIC):
        raise ProvisionError('bad_plan', f'{path}: no ESP app descriptor')
    desc = data[_APP_DESC_OFFSET:]
    version = desc[16:48].split(b'\0', 1)[0].decode('ascii', 'replace')
    project = desc[48:80].split(b'\0', 1)[0].decode('ascii', 'replace')
    return {'version': version, 'project_name': project,
            'app_elf_sha256': desc[144:176].hex()}


class Provisioner:
    """Drives one board through status → keygen → issue → seal → lock.

    `run()` is safe to re-enter after any interruption: completed stages are
    verified against live device state before they are skipped. `finalize()`
    runs after the caller's field-image write and is the only point that may
    mark the work item written/ready.
    """

    def __init__(self, journal_dir: Path, office: OfficeDriver):
        self._journal_dir = Path(journal_dir)
        self._office = office

    def journal(self, work_id: str) -> ProvisionJournal:
        return ProvisionJournal.load(self._journal_dir / f'{work_id}.journal.json')

    def run(
        self,
        plan: BoardProvisionPlan,
        link: MaintenanceLink,
        *,
        board_probe: Callable[[], str] | None = None,
    ) -> ProvisionJournal:
        """Provision identity through console-lock; resumable by construction."""
        plan.validate()
        journal = ProvisionJournal.create(self._journal_dir, plan.work_id, plan.as_dict())
        if not journal.has('plan'):
            journal.record('plan', board_mac=_normalize_mac(plan.base_mac))
        if board_probe is not None:
            probed = _normalize_mac(board_probe())
            if probed != _normalize_mac(plan.base_mac):
                raise ProvisionError(
                    'board_mismatch', f'port now serves {probed}, plan wants {plan.base_mac}'
                )
        status = self._status(journal, plan, link)
        self._keygen(journal, plan, link, status)
        issued = self._issue(journal, plan)
        sealed_kid = self._seal(journal, plan, link, issued)
        self._lock(journal, link, sealed_kid)
        return journal

    def finalize(
        self,
        plan: BoardProvisionPlan,
        link: MaintenanceLink | None = None,
        *,
        field_writer: Callable[[], str] | None = None,
        boot_log=None,
        expected_app_sha256: str = '',
    ) -> ProvisionJournal:
        """Post-field readback + office `written` commit — the only Ready gate.

        `field_writer` is the caller's ROM-session write (the existing flash
        worker); it must return the written image digest. When None the field
        image is managed outside this session and `field_digest` comes from the
        plan.

        The readback evidence is the booted field image's own report, parsed
        from `boot_log` lines (`routeloom field boot`/`sdkv1 identity`/
        `board config`); a maintenance-console `status` link is accepted as a
        fallback for flows that stay on the setup image. With neither, the
        call fails `readback_missing` — a write receipt alone is not Ready.
        """
        plan.validate()
        journal_path = self._journal_dir / f'{plan.work_id}.journal.json'
        if not journal_path.exists():
            raise ProvisionError('no_journal', f'no run() journal at {journal_path}')
        journal = ProvisionJournal.load(journal_path)
        if not journal.has('locked'):
            raise ProvisionError('not_locked', 'run() must complete before finalize')
        digest = plan.field_digest
        if field_writer is not None:
            digest = field_writer()
            _require_hex64(digest, 'field digest')
        if not journal.has('field'):
            journal.record('field', digest=digest or 'external')
        issued = journal.latest('issued')
        if issued is None:
            raise ProvisionError('bad_journal', 'seal evidence missing')
        if boot_log is not None:
            evidence = self._readback_boot(boot_log, plan, issued,
                                           expected_app_sha256)
        elif link is not None:
            evidence = self._readback_console(plan, link, issued)
        else:
            raise ProvisionError(
                'readback_missing', 'no field boot log or console link supplied')
        journal.record('readback', **evidence)
        self._office.confirm_written(
            plan.node_id, issued.get('devcert_sha256', ''), plan.out_dir
        )
        journal.record('written', node=plan.node_id)
        journal.mark_done()
        return journal

    @staticmethod
    def _readback_console(plan, link, issued) -> dict:
        status = DeviceStatus.parse(link.exchange('status'))
        if status.identity != 'sealed' or status.node != plan.node_id:
            raise ProvisionError('readback_mismatch', 'device does not hold the issued identity')
        if status.kid != issued['kid']:
            raise ProvisionError('readback_mismatch', 'kid differs from issued record')
        if status.serial != plan.serial:
            raise ProvisionError('readback_mismatch', 'serial differs from issued record')
        if issued.get('devcert_sha256') and status.devcert_sha256 != issued['devcert_sha256']:
            raise ProvisionError('readback_mismatch', 'devcert digest differs from issued record')
        if plan.fw and status.fw != plan.fw:
            raise ProvisionError('readback_mismatch', f'firmware {status.fw} != plan {plan.fw}')
        if not status.locked:
            raise ProvisionError('readback_mismatch', 'console lock did not persist')
        return {'source': 'console', 'receipt': issued['kid'], 'node': status.node,
                'kid': status.kid, 'fw': status.fw}

    @staticmethod
    def _readback_boot(boot_log, plan, issued, expected_app_sha256) -> dict:
        """Match the field boot log against the plan + issued evidence."""
        boot = parse_field_boot(boot_log)
        if boot.config_required:
            raise ProvisionError('readback_mismatch', 'field boot reported CONFIG_REQUIRED')
        if boot.identity != 'sealed' or boot.node != plan.node_id:
            raise ProvisionError(
                'readback_mismatch', 'field boot does not hold the issued identity')
        if boot.kid != issued['kid']:
            raise ProvisionError('readback_mismatch', 'boot kid differs from issued record')
        if issued.get('devcert_sha256') and \
                boot.devcert_sha256 != issued['devcert_sha256']:
            raise ProvisionError(
                'readback_mismatch', 'boot devcert digest differs from issued record')
        if boot.config_node != plan.node_id or boot.config_generation is None:
            raise ProvisionError(
                'readback_mismatch', 'board config readback missing or wrong node')
        if _normalize_mac(plan.base_mac) != (boot.config_mac or ''):
            raise ProvisionError(
                'readback_mismatch', 'board config MAC differs from the probed board')
        if plan.fw and boot.fw != plan.fw:
            raise ProvisionError(
                'readback_mismatch', f'firmware {boot.fw} != plan {plan.fw}')
        if expected_app_sha256 and boot.app_sha256 != expected_app_sha256:
            raise ProvisionError(
                'readback_mismatch', 'booted image digest differs from the signed bundle')
        return {'source': 'boot', 'node': boot.node, 'kid': boot.kid,
                'devcert_sha256': boot.devcert_sha256, 'fw': boot.fw,
                'app_sha256': boot.app_sha256,
                'config_generation': boot.config_generation,
                'secrets_generation': boot.secrets_generation}

    # --- stages -----------------------------------------------------------

    def _status(self, journal, plan, link) -> DeviceStatus:
        reply = link.exchange('status')
        if reply.startswith('ERR store_unavailable'):
            raise ProvisionError('store_unavailable', 'device identity store unreadable')
        status = DeviceStatus.parse(reply)
        journal.record('status', receipt=reply[:256])
        sealed = journal.latest('sealed')
        issued = journal.latest('issued')
        if status.identity == 'sealed':
            if status.node != plan.node_id:
                raise ProvisionError(
                    'already_provisioned',
                    f'board holds node {status.node}, plan wants {plan.node_id}',
                )
            known = issued and issued['kid'] == status.kid
            if sealed and sealed['kid'] == status.kid:
                return status  # resume after seal
            if known:
                # seal committed but the OK reply was lost — adopt the evidence
                journal.record('sealed', kid=status.kid, adopted='status-receipt')
                return status
            raise ProvisionError(
                'already_provisioned', f'board holds foreign kid {status.kid}'
            )
        # identity=none with a sealed journal entry means the board was wiped
        # (or swapped) mid-work — operator resolution, not a silent restart.
        if sealed:
            raise ProvisionError(
                'state_contradiction',
                'journal records a sealed identity but device reports none — manual check',
            )
        return status

    def _keygen(self, journal, plan, link, status: DeviceStatus):
        if journal.has('issued'):
            return
        prior = journal.latest('keygen')
        if prior and not status.pending:
            # Pending key is RAM-only: a lost pending key makes the recorded
            # PoP unusable (bound to that key), so a fresh challenge+keygen is
            # required — never replay the old PoP.
            journal.invalidate('keygen', 'pending key lost')
            prior = None
        if prior is None:
            challenge = self._office.pop_challenge(plan.node_id)
            reply = _console(link, f'keygen {plan.node_id} {challenge}')
            pop = _reply_kv(reply).get('pop_hex', '')
            if not _HEX_EVEN.match(pop):
                raise ProvisionError('bad_reply', reply[:64])
            journal.record('keygen', node=plan.node_id, challenge=challenge, pop_hex=pop)
        elif prior.get('node') != plan.node_id:
            raise ProvisionError('bad_journal', 'keygen entry for another node')

    def _issue(self, journal, plan) -> Issued:
        if journal.has('issued'):
            entry = journal.latest('issued')
            return Issued(
                kid=entry['kid'],
                devcert_sha256=entry.get('devcert_sha256', ''),
                out_dir=plan.out_dir,
            )
        keygen = journal.latest('keygen')
        issued = self._office.issue_devcert(
            plan, keygen['challenge'], keygen['pop_hex']
        )
        journal.record(
            'issued', kid=issued.kid, devcert_sha256=issued.devcert_sha256
        )
        return issued

    def _seal(self, journal, plan, link, issued: Issued) -> str:
        if journal.has('sealed'):
            return journal.latest('sealed')['kid']
        bundle_hex = self._office.bundle_hex(plan.out_dir)
        try:
            reply = _console(link, f'identity {bundle_hex}')
        except ProvisionError as exc:
            if exc.reason == 'no_pending_key':
                # The pending key is RAM-resident; losing it after the office
                # published means the bundle names a key the board no longer
                # holds. Re-keygen would produce a key the ledger slot does
                # not cover, so the operator must release it explicitly.
                raise ProvisionError(
                    'pending_lost_after_issue',
                    'pending key lost after DevCert publication; release the ledger slot and re-run',
                )
            if exc.reason in _REASONS_FATAL:
                raise
            raise ProvisionError('seal_failed', exc.reason)
        kid = _reply_kv(reply).get('kid', '')
        if kid != issued.kid:
            raise ProvisionError('seal_mismatch', f'sealed kid {kid} != issued {issued.kid}')
        journal.record('sealed', kid=kid)
        return kid

    def _lock(self, journal, link, kid: str):
        if journal.has('locked'):
            return
        reply = _console(link, f'lock {kid}')
        locked = _reply_kv(reply).get('kid', '')
        if locked != kid:
            raise ProvisionError('lock_mismatch', f'locked kid {locked} != {kid}')
        journal.record('locked', kid=kid)


class Deprovisioner:
    """Journaled formal deprovision (D03b) over the same console transport.

    The device burns the single-use challenge on confirm; a lost nonce is
    never replayed — resume always re-issues `deprovision` for a fresh nonce
    and re-verifies the shown target before confirming.
    """

    def __init__(self, journal_dir: Path):
        self._journal_dir = Path(journal_dir)

    def run(self, plan: DeprovisionPlan, link: MaintenanceLink) -> ProvisionJournal:
        plan.validate()
        journal = ProvisionJournal.create(
            self._journal_dir,
            plan.work_id,
            {
                'work_id': plan.work_id,
                'expected_node_id': plan.expected_node_id,
                'expected_kid': plan.expected_kid,
                'base_mac': plan.base_mac,
            },
        )
        if not journal.has('planned'):
            journal.record('planned', node=plan.expected_node_id)
        status = self._status_or_impaired(link)
        if status is not None and status.identity == 'none':
            journal.record('status', receipt='identity=none')
            journal.mark_done()
            return journal
        if status is not None:
            journal.record(
                'status',
                receipt=f'identity=sealed node={status.node} kid={status.kid}',
            )
            self._check_target(plan, status.node, status.kid)
        elif not plan.wipe_unverifiable and not journal.has('challenged'):
            raise ProvisionError(
                'store_unavailable',
                'target identity unreadable; pass wipe_unverifiable to wipe anyway',
            )
        for _attempt in range(2):
            challenge = _console(link, 'deprovision')
            fields = _reply_kv(challenge)
            node, kid, nonce = (
                fields.get('node', ''),
                fields.get('kid', ''),
                fields.get('nonce', ''),
            )
            if not _HEX64.match(nonce):
                raise ProvisionError('bad_reply', challenge[:64])
            if status is not None:
                # The challenged target must be exactly what the verified
                # status showed the operator moments ago.
                if node != status.node or (kid != 'none' and kid != status.kid):
                    raise ProvisionError(
                        'target_mismatch', 'challenge target changed mid-run'
                    )
            elif node != 'none' or kid != 'none':
                # An impaired store cannot name a target; only
                # wipe_unverifiable/journaled work may get here, and the
                # device answering with an identity contradicts 'impaired'.
                raise ProvisionError('target_mismatch', 'impaired store named a target')
            journal.record('challenged', node=node, kid=kid, nonce=nonce)
            try:
                reply = _console(
                    link, f'deprovision_confirm {nonce} {kid if kid else "none"}'
                )
            except ProvisionError as exc:
                if exc.reason == 'no_challenge':
                    journal.invalidate('challenged', 'challenge lost; re-issuing')
                    continue
                raise
            wiped_node = _reply_kv(reply).get('node', '')
            if wiped_node != node:
                raise ProvisionError('target_mismatch', f'wiped {wiped_node} != challenged {node}')
            journal.record('confirmed', node=wiped_node)
            break
        else:
            raise ProvisionError('challenge_lost', 'confirm lost twice; manual check required')
        try:
            post = DeviceStatus.parse(link.exchange('status'))
            if post.identity != 'none':
                raise ProvisionError('wipe_readback', 'identity still sealed after wipe')
        except ProvisionError as exc:
            if exc.reason == 'store_unavailable':
                journal.record('readback', receipt='store_unavailable')
            else:
                raise
        else:
            journal.record('readback', receipt='identity=none')
        journal.mark_done()
        return journal

    @staticmethod
    def _status_or_impaired(link) -> DeviceStatus | None:
        reply = link.exchange('status')
        if reply.startswith('ERR store_unavailable'):
            return None
        return DeviceStatus.parse(reply)

    @staticmethod
    def _check_target(plan: DeprovisionPlan, node: str, kid: str):
        if plan.expected_node_id and node != plan.expected_node_id:
            raise ProvisionError(
                'target_mismatch', f'device is node {node}, plan wants {plan.expected_node_id}'
            )
        if plan.expected_kid and kid != 'none' and kid != plan.expected_kid:
            raise ProvisionError('target_mismatch', 'device kid differs from plan')


BOOT_LOG_TIMEOUT_S = 15.0


def capture_field_boot(port: str, *, timeout_s: float = BOOT_LOG_TIMEOUT_S,
                       serial_factory=None) -> list:
    """Reset the board and collect its field-boot log lines.

    The ROM writer leaves the chip in the download stub, so a hard reset is
    always required. Captures until the identity+field+config markers have all
    been seen or the deadline expires — a silent board yields whatever lines
    arrived and the caller's readback check fails on the missing evidence.
    """
    if serial_factory is None:
        def serial_factory(path):
            import serial  # pyserial
            return serial.Serial(path, baudrate=115200, timeout=0.1)
    ser = serial_factory(port)
    try:
        # EN reset through the usual DTR/RTS auto-reset wiring; boards on
        # USB-Serial/JTAG ignore it harmlessly (their boot output arrives on
        # the same lines the port was opened for).
        for setter, value in (('dtr', False), ('rts', True)):
            try:
                setattr(ser, setter, value)
            except (OSError, AttributeError):
                pass
        time.sleep(0.1)
        for setter, value in (('rts', False), ('dtr', False)):
            try:
                setattr(ser, setter, value)
            except (OSError, AttributeError):
                pass
        try:
            ser.reset_input_buffer()
        except (OSError, AttributeError):
            pass
        deadline = time.monotonic() + timeout_s
        lines = []
        buf = b''
        seen_identity = seen_field = seen_config = False
        while time.monotonic() < deadline:
            chunk = ser.read(1024) if hasattr(ser, 'read') else b''
            if not chunk:
                if seen_identity and seen_field and seen_config:
                    break
                continue
            buf += chunk
            while b'\n' in buf:
                raw, buf = buf.split(b'\n', 1)
                text = raw.decode('ascii', 'replace').rstrip('\r')
                lines.append(text)
                seen_identity = seen_identity or 'sdkv1 identity:' in text
                seen_field = seen_field or 'routeloom field boot:' in text
                seen_config = seen_config or 'board config:' in text
            if seen_identity and seen_field and seen_config:
                # Drain one short beat for a trailing CONFIG_REQUIRED hint.
                time.sleep(0.15)
                tail = ser.read(4096) if hasattr(ser, 'read') else b''
                if tail:
                    buf += tail
                    while b'\n' in buf:
                        raw, buf = buf.split(b'\n', 1)
                        lines.append(raw.decode('ascii', 'replace').rstrip('\r'))
                break
        if buf:
            lines.append(buf.decode('ascii', 'replace').rstrip('\r'))
        return lines
    finally:
        try:
            ser.close()
        except (OSError, AttributeError):
            pass


class LabProvisionBackend(ContractBackend):
    """The real D02/D03a/D03b step implementation for development sites.

    Unlike ContractBackend this drives actual hardware: ROM probe + signed
    bundle writes through the isolated flash worker, the D02 `benchcfg`/
    `benchsecret` setup console, the D03a identity console (Provisioner), a
    field-boot log readback, and `lab-inventory-import`. Every external hook
    (boards, link, boot capture, ctl) is injectable so tests exercise the same
    orchestration without touching a device.

    Bundles are resolved per (role, chip) from `bundles_dir`: each entry must
    be an already-verified bundle directory. The setup image is the same chip
    and role built with the maintenance console enabled — its sdkconfig carries
    `CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y`.
    """

    name = 'lab'
    implemented = frozenset(STEP_NAMES[1:-1])  # plan + join stay external

    def __init__(self, *, site_dir=None, boards, bundles_dir=None,
                 ctl='routeloomctl', journal_dir=None, leases=None,
                 link_factory=None, boot_capture=None, office=None):
        from .device import PortLeases
        self.site_dir = Path(site_dir) if site_dir else None
        self.bundles_dir = Path(bundles_dir) if bundles_dir else None
        self.boards = boards
        self.ctl = ctl
        self._journal_dir = Path(journal_dir) if journal_dir else None
        # Shared with the boards screen and the supervisor when available, so
        # a daemon bridge port or a ROM probe cannot collide with a write.
        self.leases = leases if leases is not None else \
            getattr(boards, 'leases', None) or PortLeases()
        self._link_factory = link_factory or (
            lambda port: SerialMaintenanceLink(port))
        self._boot_capture = boot_capture or capture_field_boot
        self._office_override = office
        self._ctx = {}  # job.board -> per-board session state
        self._bundles = None  # lazy: {(kind, role, chip): Path}
        self._spec = None

    def configure(self, *, site_dir, bundles_dir):
        """Bind the site/bundle locations chosen in the GUI before a run."""
        self.site_dir = Path(site_dir) if site_dir else None
        self.bundles_dir = Path(bundles_dir) if bundles_dir else None
        self._bundles = None
        self._spec = None
        self._ctx.clear()

    def _journals(self):
        if self._journal_dir is not None:
            return self._journal_dir
        if self.site_dir is None:
            raise ProvisionError('no_site', 'site directory 未設定')
        return self.site_dir / 'provision-journal'

    # --- helpers --------------------------------------------------------------

    def _ctx_for(self, job):
        return self._ctx.setdefault(job.board, {})

    def _load_spec(self):
        if self.site_dir is None:
            raise ProvisionError('no_site', 'site directory 未設定')
        if self._spec is None:
            spec_path = self._spec_path()
            if not spec_path.is_file():
                raise ProvisionError(
                    'no_site', f'lab spec {spec_path} missing — run lab-site-init first')
            spec = json.loads(spec_path.read_text(encoding='utf-8'))
            if spec.get('format') != 'routeloom-lab-site-spec-v1':
                raise ProvisionError('no_site', f'{spec_path} is not a lab spec')
            self._spec = spec
        return self._spec

    def _scan_bundles(self):
        """Verify every bundle dir once; index by (console?, role, chip)."""
        if self._bundles is not None:
            return self._bundles
        from .firmware_catalog import DEV_PUBLIC_KEY, verify_bundle
        bundles = {}
        if not self.bundles_dir.is_dir():
            raise ProvisionError(
                'no_bundles', f'bundle directory {self.bundles_dir} does not exist')
        for entry in sorted(self.bundles_dir.iterdir()):
            if not entry.is_dir() or not (entry / 'manifest.json').is_file():
                continue
            try:
                manifest = verify_bundle(entry, DEV_PUBLIC_KEY)
            except ValueError:
                continue  # unsigned/invalid bundles are skipped, never half-trusted
            sdkconfig = (entry / 'sdkconfig').read_text(encoding='utf-8')
            console = 'CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y' in sdkconfig
            key = ('setup' if console else 'field',
                   manifest['role'], manifest['chip'])
            if key in bundles:
                raise ProvisionError('no_bundles',
                                     f'multiple signed bundles for {"/".join(key)}')
            bundles[key] = {'path': entry, 'manifest': manifest}
        self._bundles = bundles
        return bundles

    def _bundle(self, kind, job, chip):
        # Non-bridge boards take the bench app or the reference app
        # (build_bundle.sh builds only reference_node and bridge_node).
        roles = ('bridge_node',) if job.role == 'bridge' else ('bench_node', 'reference_node')
        bundles = self._scan_bundles()
        found = next((bundles[(kind, role, chip)] for role in roles
                      if (kind, role, chip) in bundles), None)
        if found is None:
            raise ProvisionError(
                'no_bundles',
                f'no signed {kind} bundle for {"/".join(roles)}/{chip} in {self.bundles_dir}')
        role = found['manifest']['role']
        if found['manifest'].get('generic_config') is not True:
            # Per-board NodeId comes from rlcfg; a legacy image embeds it in the
            # signed sdkconfig and would bypass the whole BoardConfig path.
            raise ProvisionError(
                'no_bundles',
                f'{role}/{chip} {kind} bundle lacks generic_config — '
                '個体別設定（BoardConfig）対応の bundle が必要')
        return found

    def _flash(self, port, bundle, identity, *, app_only=False):
        """One leased ROM session: measure + verify + write through the worker."""
        from .device import FlashPlan, Image
        manifest = bundle['manifest']
        images = tuple(Image(e['offset'], bundle['path'] / e['path'],
                             e['size'], e['sha256']) for e in manifest['files']
                       if not app_only or e['offset'] in APP_ONLY_OFFSETS)
        plan = FlashPlan(identity, manifest['chip'], images, True,
                         identity.base_mac, True, bundle['path'], None, app_only)
        with self.leases.acquire(identity.base_mac.lower(), port):
            self.boards.flash(port, plan)

    def _link(self, job, fresh=False):
        ctx = self._ctx_for(job)
        if fresh:
            self._close_link(job)
        if ctx.get('link') is None:
            ctx['link'] = self._link_factory(job.board)
        return ctx['link']

    def _close_link(self, job):
        link = self._ctx_for(job).pop('link', None)
        if link is not None:
            try:
                link.close()
            except (OSError, AttributeError):
                pass

    def _office(self, ctx):
        if self._office_override is not None:
            return self._office_override
        if ctx.get('office') is None:
            # The conventional ledger lives next to the CA key (provision_office
            # IssuanceInputs default: <ca_key>/../office-ledger.jsonl).
            ctx['office'] = CtlOffice(
                self.ctl, str(self.site_dir / 'keys' / 'device-ca.key'),
                str(self._identity_spec_path()),
                str(self.site_dir / 'keys' / 'office-ledger.jsonl'))
        return ctx['office']

    def _spec_path(self):
        return self.site_dir.parent / f'{self.site_dir.name}.lab-spec.json'

    def _identity_spec_path(self):
        """`provision-devcert --spec` takes a routeloom-identity-spec-v1, not
        the lab spec: pin the lab Site CA from site-authority.json."""
        authority = json.loads(
            (self.site_dir / 'site-authority.json').read_text(encoding='utf-8'))
        doc = {'format': 'routeloom-identity-spec-v1', 'model': 1, 'hw_rev': 1,
               'flags': 0,
               'anchors': [{'anchor_id': self._load_spec()['site_ca_id'],
                            'kind': 'site-ca', 'status': 'active',
                            'pubkey_hex': authority['site_ca_pubkey_hex']}]}
        text = json.dumps(doc, sort_keys=True)
        path = self.site_dir.parent / f'{self.site_dir.name}.identity-spec.json'
        if not path.is_file() or path.read_text(encoding='utf-8') != text:
            path.write_text(text, encoding='utf-8')
        return path

    def _site_psk(self):
        """Per-site DevRam mesh PSK, generated once and reused on retry."""
        path = self.site_dir / 'mesh-psk.key'
        if path.is_file():
            return path.read_text(encoding='utf-8').strip()
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            secret = os.urandom(32).hex()
            os.write(fd, secret.encode('ascii'))
        finally:
            os.close(fd)
        return secret

    def _usb_secret(self):
        path = self.site_dir / 'usb-dev-secret.key'
        if not path.is_file():
            raise ProvisionError('no_site', f'{path} missing — run lab-site-init first')
        secret = path.read_text(encoding='utf-8').strip()
        if not secret or len(secret) > 63 or \
                any(c < '!' or c > '~' for c in secret):
            raise ProvisionError('no_site', f'{path} is not a valid USB secret')
        return secret

    def _provisioner(self, ctx):
        if ctx.get('provisioner') is None:
            ctx['provisioner'] = Provisioner(self._journals(), self._office(ctx))
        return ctx['provisioner']

    def _plan_for(self, job, ctx, desc):
        spec = self._load_spec()
        app_entry = next(
            e for e in ctx['field_bundle']['manifest']['files']
            if e['offset'] == APP_IMAGE_OFFSET)
        serial = int.from_bytes(
            hashlib.sha256(
                f'{spec["site_id"]}:{job.node_id}'.encode()).digest()[:4], 'big')
        plan = BoardProvisionPlan(
            site_id=spec['site_id'], work_id=f'node-{job.node_id}',
            board_uuid=ctx['identity'].base_mac.lower(),
            base_mac=ctx['identity'].base_mac, node_id=job.node_id,
            serial=serial, role=job.role,
            out_dir=str(self.site_dir / 'provisioned' / job.node_id),
            fw=desc['version'],
            field_digest=app_entry['sha256'])
        return plan.validate()

    # --- ContractBackend -------------------------------------------------------

    def run(self, step, job):
        handler = getattr(self, f'_step_{step}', None)
        if handler is None:
            return StepResult('unsupported',
                              f'{STEP_OWNERS[step]} 未実装のため 未対応')
        if self.site_dir is None or self.bundles_dir is None:
            return StepResult('failed', 'site directory／bundle directory 未設定')
        try:
            return handler(job)
        except ProvisionError as exc:
            return StepResult('failed', str(exc))
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return StepResult('failed', f'{exc}')

    def _require_ctx(self, job):
        """Step context from preflight; absent only if steps skipped a stage."""
        ctx = self._ctx_for(job)
        if 'plan' not in ctx:
            raise ProvisionError(
                'bad_plan', 'preflight evidence missing — re-run the provision job')
        return ctx

    def _step_preflight(self, job):
        from .device import Identity
        port = job.board
        with self.leases.acquire(f'preflight:{port}', port):
            identity = self.boards.probe(port)
        if not isinstance(identity, Identity):
            raise ProvisionError('probe_failed', 'no ROM identity')
        if job.chip and identity.chip != job.chip:
            raise ProvisionError(
                'board_mismatch', f'chip {identity.chip} != plan {job.chip}')
        if job.base_mac and \
                _normalize_mac(identity.base_mac) != _normalize_mac(job.base_mac):
            raise ProvisionError(
                'board_mismatch',
                f'base MAC {identity.base_mac} != plan {job.base_mac}')
        ctx = self._ctx_for(job)
        ctx['identity'] = identity
        field_bundle = self._bundle('field', job, identity.chip)
        setup_bundle = self._bundle('setup', job, identity.chip)
        if (field_bundle['manifest']['security_profile'] !=
                setup_bundle['manifest']['security_profile']):
            raise ProvisionError('no_bundles', 'setup and field security profiles differ')
        ctx['field_bundle'] = field_bundle
        ctx['setup_bundle'] = setup_bundle
        ctx['desc'] = app_image_descriptor(
            field_bundle['path'] / 'images' / 'application.bin')
        ctx['plan'] = self._plan_for(job, ctx, ctx['desc'])
        manifest = field_bundle['manifest']
        return StepResult(
            'done',
            f'chip={identity.chip} mac={identity.base_mac} '
            f'field={manifest["role"]} {manifest["firmware_version"]} '
            f'({manifest["security_profile"]})',
            {'chip': identity.chip, 'base_mac': identity.base_mac})

    def _step_setup(self, job):
        ctx = self._require_ctx(job)
        plan = ctx['plan']
        journal = ProvisionJournal.create(
            self._journals(), plan.work_id, plan.as_dict())
        # Same ROM session the D03a design requires: revalidation then write.
        if not journal.has('setup_image'):
            self._close_link(job)  # the ROM writer needs exclusive port access
            self._flash(job.board, ctx['setup_bundle'], ctx['identity'])
            journal.record('setup_image', bundle=ctx['setup_bundle']['manifest']
                           ['bundle_id'])
            # The writer leaves the chip in the download stub; reset boots the
            # setup image so its maintenance console comes up.
            self._link(job, fresh=True)
        if journal.has('board_config'):
            return StepResult('done', 'board config committed（resume）',
                              dict(journal.latest('board_config')))
        manifest = ctx['field_bundle']['manifest']
        security = manifest['security_profile']
        doc = rlc1_document(
            node_id=plan.node_id, sta_mac=ctx['identity'].base_mac,
            chip=ctx['identity'].chip, role=job.role, security=security,
            channel=self._load_spec()['channel'],
            network=self._load_spec()['network_low32'])
        link = self._link(job)
        reset = getattr(link, 'reset', None)
        if reset is not None and journal.latest('setup_image'):
            reset()
        evidence = board_config_commit(
            link, doc, generation=1,
            psk_hex=self._site_psk() if security == 'dev-ram' else None,
            usb_secret=self._usb_secret() if job.role == 'bridge' else None)
        journal.record('board_config', **evidence)
        return StepResult(
            'done',
            f'board config committed generation={evidence["generation"]} '
            f'node={evidence["node"]}', evidence)

    def _step_status(self, job):
        ctx = self._require_ctx(job)
        journal = ProvisionJournal.load(
            self._journals() / f'{ctx["plan"].work_id}.journal.json')
        if journal.has('field'):
            # The field image serves no maintenance console — a `status`
            # exchange would hang on a dead link. The journaled seal is the
            # identity evidence on a resume that crossed the field write;
            # 'field' is only ever recorded after 'locked'.
            sealed = journal.latest('sealed')
            if sealed is None:
                raise ProvisionError(
                    'bad_journal', 'field written without seal evidence')
            return StepResult('done', 'identity=sealed（field・journal）',
                              {'identity': 'sealed', 'identity_mine': True,
                               'node': ctx['plan'].node_id,
                               'kid': sealed['kid']})
        status = DeviceStatus.parse(self._link(job).exchange('status'))
        mine = False
        if status.identity == 'sealed':
            issued = journal.latest('issued')
            mine = bool(issued and issued.get('kid') == status.kid)
        return StepResult('done', f'identity={status.identity}',
                          {'identity': status.identity, 'identity_mine': mine,
                           'node': status.node, 'kid': status.kid})

    def _ensure_provisioned(self, job):
        """The journaled status→lock run; idempotent across step re-entry."""
        ctx = self._require_ctx(job)
        journal = ProvisionJournal.load(
            self._journals() / f'{ctx["plan"].work_id}.journal.json')
        # 'field' implies 'locked': the whole status→lock run already
        # committed and the field image it wrote serves no maintenance
        # console, so re-verifying over it would die on a dead link.
        if journal.has('field'):
            return
        self._provisioner(ctx).run(ctx['plan'], self._link(job))

    def _step_keygen(self, job):
        self._ensure_provisioned(job)
        journal = ProvisionJournal.load(
            self._journals() / f'{self._ctx_for(job)["plan"].work_id}.journal.json')
        issued = journal.latest('issued')
        return StepResult('done', f'kid={issued["kid"][:16]}…',
                          {'kid': issued['kid']})

    def _step_issue(self, job):
        self._ensure_provisioned(job)
        journal = ProvisionJournal.load(
            self._journals() / f'{self._ctx_for(job)["plan"].work_id}.journal.json')
        issued = journal.latest('issued')
        return StepResult('done', f'devcert {issued.get("devcert_sha256", "")[:16]}…',
                          dict(issued))

    def _step_identity(self, job):
        self._ensure_provisioned(job)
        journal = ProvisionJournal.load(
            self._journals() / f'{self._ctx_for(job)["plan"].work_id}.journal.json')
        sealed = journal.latest('sealed')
        locked = journal.latest('locked')
        if not (sealed and locked):
            raise ProvisionError('seal_failed', 'journal lacks sealed/locked evidence')
        return StepResult('done', f'OK sealed kid={sealed["kid"][:16]}…',
                          {'kid': sealed['kid']})

    def _step_field(self, job):
        ctx = self._require_ctx(job)
        journal = ProvisionJournal.load(
            self._journals() / f'{ctx["plan"].work_id}.journal.json')
        if not journal.has('locked'):
            raise ProvisionError('not_locked', 'identity must seal before the field image')
        self._close_link(job)
        manifest = ctx['field_bundle']['manifest']
        if journal.has('field'):
            return StepResult('done', 'field image written（resume）')
        self._flash(job.board, ctx['field_bundle'], ctx['identity'], app_only=True)
        # Journal the write itself, not just the eventual readback: after a
        # restart the field image owns the board and its maintenance console
        # is gone — resume decisions (status/identity steps) key off this.
        journal.record('field', digest=ctx['plan'].field_digest)
        return StepResult('done', f'field {manifest["bundle_id"]} written')

    def _step_readback(self, job):
        ctx = self._require_ctx(job)
        lines = self._boot_capture(job.board)
        journal = self._provisioner(ctx).finalize(
            ctx['plan'], boot_log=lines,
            expected_app_sha256=ctx['desc']['app_elf_sha256'])
        entry = journal.latest('readback')
        # node_id/kid keys are the runner's Ready gate (provision_plan.run_job).
        return StepResult('done', f'boot readback node={entry["node"]} '
                          f'kid={entry["kid"][:16]}… gen={entry["config_generation"]}',
                          {**entry, 'node_id': entry['node']})

    def _step_inventory(self, job):
        ctx = self._require_ctx(job)
        role = 'gateway' if job.role == 'bridge' else 'endpoint'
        journal = ProvisionJournal.load(
            self._journals() / f'{ctx["plan"].work_id}.journal.json')
        if not journal.has('written'):
            raise ProvisionError('readback_missing', 'written receipt missing')
        if not journal.has('inventory'):
            self._office(ctx).import_inventory(
                str(self.site_dir), job.node_id, role)
            journal.record('inventory', node=job.node_id, role=role)
        return StepResult('done', 'inventory import 済み')


def main(argv=None, *, backend=None):
    """`python -m routeloom_meshviz.provisioning` — headless provision/deprovision.

    `provision` runs the full lab orchestration — the same
    LabProvisionBackend + ProvisionRunner steps Mesh Lab drives: ROM
    revalidation, setup image + BoardConfig, keygen/PoP/issue/seal/lock on
    the maintenance console, the field-image write, the post-boot readback
    and the inventory import. `provisioned` is printed only after readback
    matched and inventory landed; a run that stops early resumes from the
    journal on the next invocation (default location shared with Mesh Lab:
    <site>/provision-journal).
    """
    import argparse
    from .device import RealBoards
    from .provision_plan import ProvisionJob

    parser = argparse.ArgumentParser(prog='routeloom_meshviz.provisioning')
    parser.add_argument('--ctl', default='routeloomctl', help='routeloomctl path')
    parser.add_argument('--journal-dir', default=None,
                        help='journal dir (default: <site>/provision-journal)')
    sub = parser.add_subparsers(dest='verb', required=True)
    cmd = sub.add_parser('provision')
    cmd.add_argument('--port', required=True, help='board serial port')
    cmd.add_argument('--node-id', required=True, help='NodeId to assign (hex)')
    cmd.add_argument('--role', required=True, choices=LAB_ROLES)
    cmd.add_argument('--chip', default=None, help='expected chip (checked when given)')
    cmd.add_argument('--base-mac', default=None,
                     help='expected ROM base MAC (checked when given)')
    cmd.add_argument('--site-dir', required=True, help='lab site directory')
    cmd.add_argument('--bundles-dir', required=True,
                     help='signed bundle directory')
    cmd.add_argument('--baud', type=int, default=115200)
    cmd = sub.add_parser('deprovision')
    cmd.add_argument('--plan', required=True, help='plan JSON file')
    cmd.add_argument('--port', required=True, help='console serial port')
    cmd.add_argument('--baud', type=int, default=115200)
    args = parser.parse_args(argv)

    if args.verb == 'deprovision':
        if not args.journal_dir:
            parser.error('deprovision requires --journal-dir')
        plan_json = json.loads(Path(args.plan).read_text(encoding='utf-8'))
        plan = DeprovisionPlan(**plan_json)
        link = SerialMaintenanceLink(args.port, baudrate=args.baud)
        try:
            journal = Deprovisioner(args.journal_dir).run(plan, link)
        finally:
            link.close()
        print(f'deprovisioned journal={journal.path}')
        return 0

    node = valid_lab_node_id(args.node_id)
    if node is None:
        parser.error('--node-id must be 1..16 hex digits '
                     '(not 0, not the group namespace)')
    if backend is None:
        backend = LabProvisionBackend(
            site_dir=args.site_dir, boards=RealBoards(),
            bundles_dir=args.bundles_dir, ctl=args.ctl,
            journal_dir=args.journal_dir,
            link_factory=lambda port: SerialMaintenanceLink(
                port, baudrate=args.baud))
    job = ProvisionJob(args.port, args.chip, args.base_mac, args.role, node,
                       steps={'plan': 'done'})
    try:
        ProvisionRunner(backend, [job]).run_job(job)
    except Exception as exc:  # hardware/tooling failure — journal kept
        print(f'provision failed: {exc}', file=sys.stderr)
        return 1
    journal = backend._journals() / f'node-{job.node_id}.journal.json'
    if job.ready and job.steps.get('inventory') == 'done':
        print(f'provisioned node={job.node_id} journal={journal}')
        return 0
    step = job.resume_from or job.next_step() or 'join'
    detail = job.details.get(step) or job_status_text(job)
    print(f'provision stopped at {step}: {detail} '
          f'(journal={journal}; re-run to resume)', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
