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

import json
import os
import re
import shlex
import subprocess
import tempfile
import time
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
                '--node', node_id,
                '--devcert-sha256', devcert_sha256,
                '--out-dir', out_dir,
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
        link: MaintenanceLink,
        *,
        field_writer: Callable[[], str] | None = None,
    ) -> ProvisionJournal:
        """Post-field readback + office `written` commit — the only Ready gate.

        `field_writer` is the caller's ROM-session write (the existing flash
        worker); it must return the written image digest. When None the field
        image is managed outside this session and `field_digest` comes from the
        plan.
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
        status = DeviceStatus.parse(link.exchange('status'))
        issued = journal.latest('issued')
        if issued is None:
            raise ProvisionError('bad_journal', 'seal evidence missing')
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
        journal.record('readback', receipt=journal.latest('issued')['kid'])
        self._office.confirm_written(
            plan.node_id, issued.get('devcert_sha256', ''), plan.out_dir
        )
        journal.record('written', node=plan.node_id)
        journal.mark_done()
        return journal

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


def main(argv=None):
    """`python -m routeloom_meshviz.provisioning` — headless provision/deprovision."""
    import argparse

    parser = argparse.ArgumentParser(prog='routeloom_meshviz.provisioning')
    parser.add_argument('--ctl', default='routeloomctl', help='routeloomctl path')
    parser.add_argument('--journal-dir', required=True)
    sub = parser.add_subparsers(dest='verb', required=True)
    for name in ('provision', 'deprovision'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--plan', required=True, help='plan JSON file')
        cmd.add_argument('--port', required=True, help='console serial port')
        cmd.add_argument('--baud', type=int, default=115200)
        if name == 'provision':
            cmd.add_argument('--ca-key', required=True)
            cmd.add_argument('--spec', required=True)
            cmd.add_argument('--ledger', required=True)
    args = parser.parse_args(argv)

    link = SerialMaintenanceLink(args.port, baudrate=args.baud)
    try:
        if args.verb == 'provision':
            plan_json = json.loads(Path(args.plan).read_text(encoding='utf-8'))
            plan = BoardProvisionPlan(**plan_json)
            office = CtlOffice(args.ctl, args.ca_key, args.spec, args.ledger)
            journal = Provisioner(args.journal_dir, office).run(plan, link)
            print(f'provisioned node={plan.node_id} journal={journal.path}')
        else:
            plan_json = json.loads(Path(args.plan).read_text(encoding='utf-8'))
            plan = DeprovisionPlan(**plan_json)
            journal = Deprovisioner(args.journal_dir).run(plan, link)
            print(f'deprovisioned journal={journal.path}')
    finally:
        link.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
