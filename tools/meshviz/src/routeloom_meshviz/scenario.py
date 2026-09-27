"""Declarative lab scenario runner (design-devflow D12).

A scenario is a single JSON document — `routeloom-lab-scenario-v1` — that
declares the whole dev-site exercise: provision, join, rollcall, traffic,
revoke/GK/cutover, drain and report. JSON is a YAML subset, so the file is
still a valid YAML document; arbitrary YAML object construction is rejected
by construction (the loader is `json.loads`, nothing else ever runs).

Execution model mirrors `trial.TrialRunner`: the runner is transport- and
Qt-free — `due(now_ms)` returns `Call` objects the caller ships over the
API1 socket or the device channel, `on_reply(tag, reply, now_ms)` feeds
answers back. Every step/op transition lands in an fsync'd journal before
the corresponding call is emitted, so a resume after interruption can
reconcile exactly what was in flight — never assume, never silently retry.
"""

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import rlb1

SCHEMA = 'routeloom-lab-scenario-v1'
JOURNAL_FORMAT = 'routeloom-scenario-journal-v1'

# Runner states per D12: Draft → Validated → Armed → Running → Draining →
# Completed | Failed | Aborted | Incomplete.
STATE_RUNNING = 'Running'
STATE_DRAINING = 'Draining'
STATE_TERMINAL = ('Completed', 'Failed', 'Aborted', 'Incomplete')

# Step states: pending → running → done | skipped | failed | incomplete.
# `skipped` is a *planned* skip (step optional:true failed) — recorded, never
# hidden; `incomplete` means evidence ran out under us (reconcile failed).

# Dangerous steps have ZERO unconditional retries: a lost reply or reconcile
# failure ends the step `incomplete` — the same operation may only be
# re-delivered under its recorded idempotency key, never blindly re-issued.
STEP_DEFS = {
    # kind: (channel, dangerous, allowed keys beyond the common ones)
    'record_start': ('local', False, {'path', 'label'}),
    'flash_provision': ('device', True, {'targets', 'bundle'}),
    'gateway_join': ('api1', False, {'gateway'}),
    'join_policy': ('api1', False, {'policy'}),
    'sequential_power_on': ('device', False, {'targets', 'settle_ms'}),
    'formation_wait': ('api1', False, {'count'}),
    'rollcall': ('api1', False, {'action', 'group'}),
    'ping': ('api1', False, {'to', 'count', 'interval_ms', 'payload_len', 'ttl_ms'}),
    # peer_send/soak are device-generated traffic (D10/D12): the runner
    # issues bounded RLB1 generator commands on the bench channel — the
    # device, not the host, produces the data packets (design §5.2/§7.4).
    # They are dangerous like the other state-mutating steps: a timeout means
    # the generator's fate is unproven → incomplete, never a claimed failure.
    'peer_send': ('bench', True, {'pairs', 'count', 'interval_ms', 'payload_len',
                                  'ttl_ms', 'seed'}),
    'control_send': ('api1', False, {'target', 'period_ms', 'duration_ms',
                                     'payload_len'}),
    'soak': ('bench', True, {'pairs', 'duration_ms', 'interval_ms',
                             'payload_len', 'ttl_ms', 'seed',
                             'max_data_messages'}),
    'drain': (None, False, set()),
    'reset_rejoin': ('device', True, {'target'}),
    'exclusion': ('api1', True, {'target', 'reason', 'expected_generation'}),
    'gk_rotate': ('api1', True, {'expected_active_epoch'}),
    'cutover': ('api1', True, {'expected_site_epoch', 'next_site_cert'}),
    'report': ('local', False, {'formats', 'path'}),
}
COMMON_STEP_KEYS = {'id', 'kind', 'optional', 'note', 'timeout_ms'}

MAX_STEPS = 64
MAX_TARGETS = 256
MAX_DURATION_MS = 24 * 60 * 60 * 1000          # a scenario is at most one day
DEFAULT_STEP_TIMEOUT_MS = 120_000
POLL_MS = 2_000
REPLY_TIMEOUT_MS = 10_000
HEX_ID_LEN = 16
PAYLOAD_MAX_NODE = 128                         # NORMAL_PAYLOAD_MAX
# KG display floor (D10): a control display stream must sustain at least
# 12 messages/minute per destination — period ≤ 5000ms.
CONTROL_PERIOD_MAX_MS = 5_000
BENCH_RUN_WINDOW_CALLS = 64
BENCH_RUN_WINDOW_MS = 60_000
BENCH_INFLIGHT_MAX = 4

# bench_node generator bounds (components/routeloom_bench/app.hpp): a run is
# at most 64 packets or 60 s, whichever first; every packet body carries the
# 8-byte destination-boot bind prefix, so payload_len is at least 8.
GEN_MAX_COUNT = 64
GEN_MAX_RUN_MS = 60_000
GEN_PAYLOAD_MIN = 8
GEN_PAYLOAD_MAX = 96                        # RLB1 body bound on unicast
GEN_TTL_MAX_MS = 30_000                     # kMaxMessageLifetimeMs
MAX_PAIRS = 8
# Bounded-interval collection: the runner polls generator status every
# BENCH_STATUS_POLL_MS while a run is live.
BENCH_STATUS_POLL_MS = 5_000
# One command per phase gets at most one same-(run,seq) re-issue — the
# device dedups commands, so the retry can never mint a second run.
BENCH_PHASE_ATTEMPTS = 2
# After soak's duration ends, an in-flight run gets this drain allowance
# inside the step deadline before the step is called unverifiable.
SOAK_DRAIN_SLACK_MS = 90_000
MAX_BENCH_RUNS_PER_STEP = 512

# Device-channel ops a caller-side driver implements. `provision` maps onto
# provisioning.Provisioner (D03a/b journaled flow); `power_on`/`reset` are
# board power control — USB disconnect is never accepted as a substitute.
DEVICE_OPS = {'provision', 'power_on', 'reset'}


class ScenarioError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f'{code}: {detail}')
        self.code = code
        self.detail = detail


def _is_hex_id(value, length=HEX_ID_LEN):
    return (isinstance(value, str) and len(value) == length and
            all(c in '0123456789abcdefABCDEF' for c in value))


def _is_idem_key(value):
    return isinstance(value, str) and 8 <= len(value) <= 64 and \
        all(c in '0123456789abcdefABCDEF-_' for c in value)


def bench_run_ms(count: int, interval_ms: int) -> int:
    """One generator run's nominal data span — the device caps it at
    GEN_MAX_RUN_MS regardless of pace."""
    return min(count * interval_ms, GEN_MAX_RUN_MS)


def bench_calls_per_run(run_ms: int) -> int:
    """Host admission calls for one bounded run: hello×2 + start + status
    polls over the run's life + count_get (+ the stop on a drain path)."""
    return 4 + run_ms // BENCH_STATUS_POLL_MS + 1


def bench_calls_per_minute() -> int:
    """Admission demand while a run is live: one status poll per interval."""
    return 60_000 // BENCH_STATUS_POLL_MS + 5


PEER_SEND_RESULT_NAMES = {
    rlb1.PS_QUERY: 'query', rlb1.PS_STARTED: 'started',
    rlb1.PS_DUPLICATE: 'duplicate', rlb1.PS_STALE_BOOT: 'stale_boot',
    rlb1.PS_BUSY: 'busy', rlb1.PS_INVALID: 'invalid',
    rlb1.PS_STOPPED: 'stopped', rlb1.PS_NOT_RUNNING: 'not_running'}

GEN_STATE_NAMES = {
    rlb1.GEN_IDLE: 'idle', rlb1.GEN_RUNNING: 'running',
    rlb1.GEN_COMPLETE: 'complete', rlb1.GEN_STOPPED: 'stopped',
    rlb1.GEN_TIME_BOUND: 'time_bound', rlb1.GEN_PEER_RESET: 'peer_reset'}


def peer_send_result_name(code) -> str:
    return PEER_SEND_RESULT_NAMES.get(code, f'result_{code}')


def gen_state_name(state) -> str:
    return GEN_STATE_NAMES.get(state, f'state_{state}')


def load_document(text: str) -> dict:
    """Strict JSON load — the only accepted surface (YAML-superset grammar)."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ScenarioError('bad_document', str(exc)) from exc
    if not isinstance(doc, dict):
        raise ScenarioError('bad_document', 'scenario must be a JSON object')
    return doc


def load_document_file(path) -> dict:
    return load_document(Path(path).read_text(encoding='utf-8'))


def validate(doc: dict, capacity: dict | None = None) -> list[str]:
    """Static long-plan validation (D10/D12): every rule that can be checked
    before arming runs here — schema, step set, targets, duration, admission
    budget, storage estimate, dangerous-op scoping. `capacity` is the daemon's
    `capacity.get` result; when given, admission budgets are checked against
    the enforced profile rather than the declared limits.
    Returns a list of problems; empty means the plan is validatable.
    """
    errors = []
    if doc.get('schema') != SCHEMA:
        errors.append(f'schema must be "{SCHEMA}"')
        return errors                       # nothing else is well-defined
    if not _is_hex_id(doc.get('network')):
        errors.append('network must be a 16-hex string')
    limits = doc.get('limits', {})
    if not isinstance(limits, dict):
        errors.append('limits must be an object')
        limits = {}
    for key in ('duration_max_ms', 'calls_per_minute', 'inflight_max'):
        if key in limits and (type(limits[key]) is not int or limits[key] <= 0):
            errors.append(f'limits.{key} must be a positive integer')
    nodes = doc.get('nodes', {})
    if not isinstance(nodes, dict):
        errors.append('nodes must be an object mapping hex ids to metadata')
        nodes = {}
    for node in nodes:
        if not _is_hex_id(node):
            errors.append(f'nodes key "{node}" is not a 16-hex id')
    declared = {k.lower() for k in nodes}

    steps = doc.get('steps')
    if not isinstance(steps, list) or not steps:
        errors.append('steps must be a non-empty list')
        return errors
    if len(steps) > MAX_STEPS:
        errors.append(f'steps exceeds {MAX_STEPS}')

    # Admission budget: the enforced daemon profile wins when known.
    admission = (capacity or {}).get('admission', {}) if isinstance(capacity, dict) else {}
    rate_limit = admission.get('calls_per_minute') or limits.get('calls_per_minute', 2)
    inflight_max = limits.get('inflight_max', 4)
    total_calls = 0                        # admission-charged calls
    worst_minute = 0                       # calls in any single 60s window
    total_duration = 0
    seen_ids = set()

    for index, step in enumerate(steps):
        where = f'steps[{index}]'
        if not isinstance(step, dict):
            errors.append(f'{where} must be an object')
            continue
        kind = step.get('kind')
        if kind not in STEP_DEFS:
            errors.append(f'{where}: unknown kind "{kind}"')
            continue
        channel, dangerous, allowed = STEP_DEFS[kind]
        for key in step:
            if key not in allowed | COMMON_STEP_KEYS:
                errors.append(f'{where}: unknown key "{key}"')
        step_id = step.get('id', f's{index}')
        if not isinstance(step_id, str) or not step_id:
            errors.append(f'{where}: id must be a non-empty string')
        elif step_id in seen_ids:
            errors.append(f'{where}: duplicate id "{step_id}"')
        seen_ids.add(step_id)
        if 'optional' in step and type(step['optional']) is not bool:
            errors.append(f'{where}: optional must be a boolean')
        timeout = step.get('timeout_ms', DEFAULT_STEP_TIMEOUT_MS)
        if type(timeout) is not int or timeout <= 0:
            errors.append(f'{where}: timeout_ms must be a positive integer')
            timeout = DEFAULT_STEP_TIMEOUT_MS
        total_duration += timeout

        def target_list(name):
            value = step.get(name)
            ids = value if isinstance(value, list) else ([value] if value is not None else [])
            out = []
            for t in ids:
                if not _is_id_or_declared(t):
                    errors.append(f'{where}: bad target "{t}" (16-hex id or declared node)')
                else:
                    out.append(_target_id(t))
            if not ids:
                errors.append(f'{where}: {name} requires at least one target')
            if len(out) > MAX_TARGETS:
                errors.append(f'{where}: too many targets ({len(out)} > {MAX_TARGETS})')
            return out

        def _is_id_or_declared(t):
            if _is_hex_id(t):
                return True
            return isinstance(t, str) and t in declared

        def _target_id(t):
            return t if _is_hex_id(t) else t  # declared names resolve at arm time

        def pair_list():
            """peer_send/soak 'pairs': a list of [src, dst] (or {src,dst})
            naming bench endpoints; aliases resolve at arm time."""
            raw = step.get('pairs')
            out = []
            if not isinstance(raw, list) or not raw:
                errors.append(f'{where}: pairs must be a non-empty list of [src,dst]')
                return out
            if len(raw) > MAX_PAIRS:
                errors.append(f'{where}: pairs exceeds {MAX_PAIRS}')
                return out
            for p in raw:
                if isinstance(p, dict):
                    pair = (p.get('src'), p.get('dst'))
                elif isinstance(p, (list, tuple)) and len(p) == 2:
                    pair = (p[0], p[1])
                else:
                    errors.append(f'{where}: pair must be [src,dst]')
                    continue
                src, dst = pair
                if not _is_id_or_declared(src) or not _is_id_or_declared(dst):
                    errors.append(f'{where}: bad pair "{p}" (16-hex ids or declared nodes)')
                    continue
                if isinstance(src, str) and isinstance(dst, str) and \
                        src.lower() == dst.lower():
                    errors.append(f'{where}: pair src == dst')
                    continue
                out.append((src, dst))
            return out

        def bounded_int(name, lo, hi, required=False):
            v = step.get(name)
            if v is None and not required:
                return None
            if type(v) is not int or not lo <= v <= hi:
                errors.append(f'{where}: {name} must be an integer in [{lo},{hi}]')
                return lo
            return v

        if kind == 'flash_provision':
            target_list('targets')
            bundle = step.get('bundle')
            if not isinstance(bundle, dict) or not isinstance(bundle.get('digest'), str) \
                    or not bundle['digest'].startswith('sha256:') \
                    or not isinstance(bundle.get('signature'), str):
                errors.append(f'{where}: bundle requires digest "sha256:..." and signature')
        elif kind == 'sequential_power_on':
            target_list('targets')
            bounded_int('settle_ms', 0, 600_000)
        elif kind == 'formation_wait':
            bounded_int('count', 1, MAX_TARGETS, required=True)
        elif kind == 'gateway_join':
            target_list('gateway')
        elif kind == 'rollcall':
            if step.get('action') not in ('start', 'stop', 'status'):
                errors.append(f'{where}: action must be start|stop|status')
        elif kind == 'ping':
            targets = target_list('to')
            count = bounded_int('count', 1, 4096, required=True)
            interval = bounded_int('interval_ms', 50, 3_600_000, required=True)
            # Round-robin emits one submit per interval: the worst minute is
            # bounded by both the plan size and the paced rate.
            sends = count * max(1, len(targets))
            total_calls += sends
            worst_minute = max(worst_minute,
                               min(sends, -(-60_000 // max(interval, 1))))
            bounded_int('payload_len', 0, PAYLOAD_MAX_NODE)
        elif kind in ('peer_send', 'soak'):
            # Both kinds drive bench_node generators: the host submits only
            # the bounded RLB1 commands (hello/start/polls/stop/count_get);
            # the device owns the data packets. Admission cost is the
            # command count, never count×pairs packets.
            pairs = pair_list()
            interval = bounded_int('interval_ms', 50, 600_000, required=True)
            bounded_int('payload_len', GEN_PAYLOAD_MIN, GEN_PAYLOAD_MAX)
            bounded_int('ttl_ms', 1, GEN_TTL_MAX_MS)
            seed = step.get('seed')
            if seed is not None and (type(seed) is not int or
                                     not 0 <= seed <= 0xFFFFFFFF):
                errors.append(f'{where}: seed must be a u32')
            if kind == 'peer_send':
                count = bounded_int('count', 1, GEN_MAX_COUNT, required=True)
                run_ms = bench_run_ms(count, interval)
                if count * interval > GEN_MAX_RUN_MS:
                    errors.append(f'{where}: count*interval_ms exceeds the device '
                                  f'{GEN_MAX_RUN_MS}ms run bound')
                calls = len(pairs) * bench_calls_per_run(run_ms) + 1
                total_calls += calls
                if timeout < len(pairs) * (run_ms + 15_000):
                    errors.append(f'{where}: timeout_ms must cover {len(pairs)} '
                                  f'sequential bounded runs (~{run_ms}ms each + drain)')
            else:
                duration = bounded_int('duration_ms', 1000, MAX_DURATION_MS,
                                       required=True)
                bounded_int('max_data_messages', 1, 1_000_000)
                count_per_run = min(GEN_MAX_COUNT,
                                    max(1, GEN_MAX_RUN_MS // max(interval, 1)))
                run_ms = bench_run_ms(count_per_run, interval)
                runs = -(-duration // run_ms) if run_ms else 0
                calls = runs * bench_calls_per_run(run_ms) + 1
                total_calls += calls
                # The step deadline must outlive the soak plus one run's
                # drain — a tighter timeout would truncate interval evidence.
                if timeout < duration + SOAK_DRAIN_SLACK_MS:
                    errors.append(f'{where}: timeout_ms must be >= duration_ms + '
                                  f'{SOAK_DRAIN_SLACK_MS} (bounded-interval drain)')
                total_duration += max(0, duration + SOAK_DRAIN_SLACK_MS - timeout)
            worst_minute = max(worst_minute, bench_calls_per_minute())
        elif kind == 'control_send':
            target_list('target')
            period = bounded_int('period_ms', 100, 600_000, required=True)
            duration = bounded_int('duration_ms', 1000, MAX_DURATION_MS, required=True)
            calls = (duration + period - 1) // period
            total_calls += calls
            worst_minute = max(worst_minute, (60_000 + period - 1) // period)
            if period > CONTROL_PERIOD_MAX_MS:
                errors.append(
                    f'{where}: period_ms {period} cannot sustain the 12/min display floor '
                    f'(max {CONTROL_PERIOD_MAX_MS})')
            bounded_int('payload_len', 0, PAYLOAD_MAX_NODE)
        elif kind == 'soak':
            pairs = pair_list()
            duration = bounded_int('duration_ms', 1000, MAX_DURATION_MS, required=True)
            interval = bounded_int('interval_ms', 50, 600_000, required=True)
            bounded_int('max_data_messages', 1, 1_000_000)
            count_per_run = min(GEN_MAX_COUNT, max(1, GEN_MAX_RUN_MS // interval))
            run_ms = bench_run_ms(count_per_run, interval)
            runs = -(-duration // run_ms) if run_ms else 0
            calls = runs * bench_calls_per_run(run_ms) + 1
            total_calls += calls
            worst_minute = max(worst_minute, bench_calls_per_minute())
            # The step deadline must outlive the soak plus one run's drain —
            # a tighter timeout would truncate an interval's evidence.
            if timeout < duration + SOAK_DRAIN_SLACK_MS:
                errors.append(f'{where}: timeout_ms must be >= duration_ms + '
                              f'{SOAK_DRAIN_SLACK_MS} (bounded-interval drain)')
            total_duration += max(0, duration + SOAK_DRAIN_SLACK_MS - timeout)
        elif kind == 'reset_rejoin':
            target_list('target')
        elif kind == 'exclusion':
            target_list('target')
            # membership.revoke requires both fields — omitting either is a
            # daemon-side INVALID_ARGUMENT the validator should catch first.
            bounded_int('expected_generation', 1, 2**32 - 1, required=True)
            reason = step.get('reason')
            if reason not in ('removed', 'lost', 'replaced', 'blocked'):
                errors.append(f'{where}: reason must be removed|lost|replaced|blocked')
        elif kind == 'gk_rotate':
            bounded_int('expected_active_epoch', 1, 2**32 - 1, required=True)
        elif kind == 'cutover':
            bounded_int('expected_site_epoch', 1, 2**32 - 1, required=True)
            cert = step.get('next_site_cert')
            if not isinstance(cert, str) or not cert or len(cert) % 2 or \
                    len(cert) > 2048 or \
                    any(c not in '0123456789abcdefABCDEF' for c in cert):
                errors.append(f'{where}: next_site_cert must be even-length hex '
                              f'(≤1024 bytes)')
        elif kind == 'join_policy':
            policy = step.get('policy')
            if not isinstance(policy, dict) or not policy:
                errors.append(f'{where}: policy must be a non-empty object')
            else:
                for key in policy:
                    if key not in ('zero_touch_open', 'decision_mode',
                                   'decision_timeout_ms', 'pending_retry_after_s'):
                        errors.append(f'{where}: unknown policy key "{key}"')
                if 'zero_touch_open' in policy and \
                        type(policy['zero_touch_open']) is not bool:
                    errors.append(f'{where}: policy.zero_touch_open must be a boolean')
                if 'decision_mode' in policy and \
                        policy['decision_mode'] not in ('kguard', 'closed'):
                    errors.append(f'{where}: policy.decision_mode must be kguard|closed')
                for key, lo, hi in (('decision_timeout_ms', 500, 5000),
                                    ('pending_retry_after_s', 30, 3600)):
                    if key in policy and (type(policy[key]) is not int
                                          or not lo <= policy[key] <= hi):
                        errors.append(f'{where}: policy.{key} must be an integer '
                                      f'in [{lo},{hi}] (daemon-enforced range)')
        elif kind == 'drain':
            pass
        elif kind == 'report':
            formats = step.get('formats', ['json'])
            if not isinstance(formats, list) or \
                    any(f not in ('json', 'csv', 'markdown') for f in formats):
                errors.append(f'{where}: formats must be a list of json|csv|markdown')
            if 'path' in step and not isinstance(step['path'], str):
                errors.append(f'{where}: path must be a string')

    duration_limit = limits.get('duration_max_ms', MAX_DURATION_MS)
    if total_duration > duration_limit:
        errors.append(f'plan duration {total_duration}ms exceeds limits.duration_max_ms '
                      f'{duration_limit}ms')
    # Admission budget: total calls must fit the profile for the plan's
    # runtime AND any single minute must not outpace the sustained rate.
    total_seconds = max(total_duration / 1000, 60)
    if total_calls / total_seconds * 60 > rate_limit:
        errors.append(f'plan needs ~{total_calls} admission calls over {total_duration}ms '
                      f'(>{rate_limit}/min sustained)')
    if worst_minute > rate_limit:
        errors.append(f'worst-minute admission demand {worst_minute} exceeds '
                      f'{rate_limit}/min — pace the steps or use a bench profile')
    # Store footprint estimate: every admitted call is a record. A plan may
    # not consume the entire store — the epoch and any concurrent traffic
    # need headroom.
    store = (capacity or {}).get('store', {}) if isinstance(capacity, dict) else {}
    records_max = store.get('records_max', 4096)
    if total_calls >= records_max:
        errors.append(f'plan needs {total_calls} records, store holds {records_max}')
    if inflight_max and worst_minute > 0 and inflight_max < 1:
        errors.append('limits.inflight_max must be >= 1')
    return errors


@dataclass
class Call:
    """One outbound unit of work the caller ships: channel + payload."""
    tag: str
    channel: str          # 'api1' | 'device' | 'local'
    method: str           # api1 verb or device op name
    params: dict
    step: int
    idempotency_key: str | None = None


@dataclass
class Op:
    """Journal-tracked operation record — the reconcile ledger."""
    tag: str
    step: int
    channel: str
    method: str
    sent_ms: int
    status: str = 'sent'             # sent | replied | reconciled | lost
    reply_ms: int | None = None
    ok: bool | None = None
    code: str | None = None
    result: dict | None = None
    idempotency_key: str | None = None
    params: dict | None = None
    reconciles: str | None = None    # set on the op re-issued FOR a lost op


@dataclass
class StepState:
    index: int
    id: str
    kind: str
    spec: dict
    status: str = 'pending'          # pending|running|done|skipped|failed|incomplete
    started_ms: int | None = None
    ended_ms: int | None = None
    detail: dict = field(default_factory=dict)
    # send-step pacing
    next_index: int = 0
    next_at_ms: int = 0
    deadline_ms: int | None = None


class ScenarioJournal:
    """Append-only fsync'd run journal; the single source of truth for resume."""

    def __init__(self, path: Path, doc: dict):
        self.path = Path(path)
        self._doc = doc

    @classmethod
    def create(cls, journal_dir, run_id: str, scenario: dict) -> 'ScenarioJournal':
        Path(journal_dir).mkdir(parents=True, exist_ok=True)
        path = Path(journal_dir) / f'{run_id}.scenario.json'
        canonical = json.dumps(scenario, sort_keys=True, separators=(',', ':'))
        doc = {'format': JOURNAL_FORMAT, 'run_id': run_id,
               'created_wall': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
               'scenario_hash': hashlib.sha256(canonical.encode()).hexdigest(),
               'scenario': scenario, 'entries': [], 'state': 'Armed', 'done': False}
        journal = cls(path, doc)
        journal._write()
        return journal

    @classmethod
    def load(cls, path) -> 'ScenarioJournal':
        path = Path(path)
        doc = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(doc, dict) or doc.get('format') != JOURNAL_FORMAT:
            raise ScenarioError('bad_journal', str(path))
        if not isinstance(doc.get('entries'), list) or not isinstance(doc.get('scenario'), dict):
            raise ScenarioError('bad_journal', str(path))
        return cls(path, doc)

    def _write(self):
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self._doc, indent=2, sort_keys=True) + '\n', encoding='utf-8')
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

    def record(self, entry: dict):
        entry = {'wall': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **entry}
        self._doc['entries'].append(entry)
        self._write()

    def set_state(self, state: str):
        self._doc['state'] = state
        if state in STATE_TERMINAL:
            self._doc['done'] = True
        self._write()

    @property
    def entries(self) -> list:
        return self._doc['entries']

    @property
    def state(self) -> str:
        return self._doc['state']

    @property
    def run_id(self) -> str:
        return self._doc['run_id']

    @property
    def done(self) -> bool:
        return bool(self._doc.get('done'))


class ScenarioRunner:
    """Draft → Validated → Armed → Running → Draining → terminal.

    `due(now_ms)` yields `Call`s the caller must transport; `on_reply` feeds
    decoded responses (or None on transport loss). Timeouts, reconciliation
    and step sequencing all live here — the transport layer is dumb.
    """

    def __init__(self, doc: dict, journal: ScenarioJournal, *, now_ms: int = 0,
                 capacity: dict | None = None):
        errors = validate(doc, capacity)
        if errors:
            raise ScenarioError('invalid_plan', '; '.join(errors))
        self.doc = doc
        self.journal = journal
        self.capacity = capacity or {}
        self.network = doc['network'].lower()
        self.limits = doc.get('limits', {})
        nodes = doc.get('nodes', {})
        # Declared aliases → hex ids (lowercase keys match the validator).
        self.aliases = {k.lower(): k.lower() for k in nodes}
        self.steps = [StepState(index=i, id=s.get('id', f's{i}'), kind=s['kind'], spec=s)
                      for i, s in enumerate(doc['steps'])]
        self.state = 'Armed'
        self.step_index = 0
        self.outstanding: dict[str, Op] = {}
        self.epoch: str | None = None
        self.epoch_pending = False
        self.epoch_retry_at_ms = 0
        self.tag_counter = 0
        self.ops: list[Op] = []
        self.gaps: list[dict] = []
        self.stop_reason = None
        self._last_emit_ms: int | None = None
        self._last_tick_ms: int | None = None
        self._ready: list[Call] = []
        self.results = []                  # finalized per-send ledger rows
        journal.set_state('Armed')

    # -- construction / resume ------------------------------------------------

    @classmethod
    def arm(cls, doc: dict, journal_dir, *, now_ms: int = 0, capacity=None,
            run_id: str | None = None) -> 'ScenarioRunner':
        journal = ScenarioJournal.create(journal_dir, run_id or uuid.uuid4().hex, doc)
        return cls(doc, journal, now_ms=now_ms, capacity=capacity)

    @classmethod
    def resume(cls, journal: ScenarioJournal, *, now_ms: int = 0,
               capacity=None) -> 'ScenarioRunner':
        """Rebuild a runner from its journal. In-flight ops that never got a
        reply are reconciled — `operations.get_by_key` for submits, same-key
        re-issue for the site verbs — and anything unverifiable lands the
        step/run in `incomplete`, never a silent assume-success."""
        doc = journal._doc['scenario']
        errors = validate(doc, capacity)
        if errors:
            raise ScenarioError('invalid_plan', '; '.join(errors))
        runner = cls.__new__(cls)
        runner.doc = doc
        runner.journal = journal
        runner.capacity = capacity or {}
        runner.network = doc['network'].lower()
        runner.limits = doc.get('limits', {})
        nodes = doc.get('nodes', {})
        runner.aliases = {k.lower(): k.lower() for k in nodes}
        runner.steps = [StepState(index=i, id=s.get('id', f's{i}'), kind=s['kind'], spec=s)
                        for i, s in enumerate(doc['steps'])]
        runner.state = journal.state if journal.state not in STATE_TERMINAL else 'Incomplete'
        runner.step_index = 0
        runner.outstanding = {}
        runner.epoch = None
        runner.epoch_pending = False
        runner.epoch_retry_at_ms = 0
        runner.tag_counter = 0
        runner.ops = []
        runner.gaps = []
        runner.stop_reason = None
        runner._last_emit_ms = None
        runner._last_tick_ms = None
        runner._ready = []
        runner.results = []

        # Fold the journal: step transitions and op records.
        unresolved = []
        for entry in journal.entries:
            kind = entry.get('type')
            if kind == 'step':
                index = entry['index']
                step = runner.steps[index]
                step.status = entry['status']
                step.detail.update(entry.get('detail', {}))
                step.started_ms = entry.get('started_ms', step.started_ms)
                step.ended_ms = entry.get('ended_ms', step.ended_ms)
            elif kind == 'op':
                # The journal holds one row per transition — fold by tag so a
                # sent+replied pair yields ONE op record in the ledger.
                existing = next((o for o in runner.ops if o.tag == entry['tag']), None)
                if existing is None:
                    existing = Op(tag=entry['tag'], step=entry['step'],
                                  channel=entry['channel'], method=entry['method'],
                                  sent_ms=entry['sent_ms'],
                                  idempotency_key=entry.get('idempotency_key'),
                                  params=entry.get('params'))
                    runner.ops.append(existing)
                    runner.tag_counter += 1
                    unresolved.append(existing)
                existing.reconciles = entry.get('reconciles', existing.reconciles)
                existing.status = entry['status']
                existing.reply_ms = entry.get('reply_ms')
                existing.ok = entry.get('ok')
                existing.code = entry.get('code')
                existing.result = entry.get('result')
                if entry['status'] != 'sent' and existing in unresolved:
                    unresolved.remove(existing)
            elif kind == 'epoch':
                runner.epoch = entry.get('epoch')
            elif kind == 'skip':
                # A planned-late slot consumes its index on resume too — the
                # deterministic key space stays aligned with the journal.
                runner.results.append({'step': entry['step'],
                                       'index': entry['index'], 'target': None,
                                       'key': None,
                                       'planned_ms': entry.get('planned_ms'),
                                       'submit_ms': None,
                                       'result': 'skipped_late'})
            elif kind == 'gap':
                runner.gaps.append(entry)
            elif kind == 'stop':
                runner.stop_reason = entry.get('reason')
        # Steps before the first non-done one resume; the running step's
        # unresolved ops get reconcile calls in `due`.
        for i, step in enumerate(runner.steps):
            if step.status in ('running', 'pending'):
                runner.step_index = i
                break
        else:
            runner.step_index = len(runner.steps)
        for op in unresolved:
            runner.outstanding[op.tag] = op
            step = runner.steps[op.step]
            if step.status == 'running':
                step.detail['reconcile_pending'] = True
        # Rebuild the per-send ledger: 'send' journal rows carry the true
        # per-index identity (a rate-limit retry re-emits under the SAME
        # index — counting submit ops would overcount). Journals predating
        # send rows fall back to op enumeration.
        sends = [e for e in journal.entries if e.get('type') == 'send']
        for step in runner.steps:
            step_sends = [e for e in sends if e.get('step') == step.index]
            if step_sends:
                by_key = {}
                for o in runner.ops:
                    if o.step == step.index and o.method == 'messages.submit' \
                            and o.params:
                        by_key[o.params.get('key')] = o
                by_index = {}
                for e in step_sends:
                    # A retry re-journals the same index — one ledger row per
                    # planned send; the last emit carries the latest submit_ms.
                    row = by_index.get(e['index'])
                    o = by_key.get(e.get('key'))
                    if row is None:
                        row = {'step': step.index, 'index': e['index'],
                               'target': e.get('target'),
                               'key': e.get('key'),
                               'planned_ms': e.get('ms'),
                               'submit_ms': e.get('ms')}
                        by_index[e['index']] = row
                        runner.results.append(row)
                    else:
                        row['submit_ms'] = e.get('ms')
                    row['result'] = ('admitted' if o and o.ok is True
                                     else 'retry_pending'
                                     if o and o.code == 'RATE_LIMITED'
                                     else 'submitted' if o else 'unknown')
                continue
            subs = [o for o in runner.ops
                    if o.step == step.index and o.method == 'messages.submit'
                    and o.params]
            seen_keys = set()
            for o in subs:
                key = (o.params or {}).get('key')
                if key in seen_keys:
                    continue                    # same-index retry re-emit
                seen_keys.add(key)
                dest = (o.params or {}).get('destination') or {}
                runner.results.append({'step': step.index,
                                       'index': len(seen_keys) - 1,
                                       'target': dest.get('id'),
                                       'key': key,
                                       'planned_ms': o.sent_ms,
                                       'submit_ms': o.sent_ms,
                                       'result': 'admitted' if o.ok is True
                                       else 'retry_pending'
                                       if o.code == 'RATE_LIMITED'
                                       else 'submitted'})
        # Already-answered reconciles apply their verdict to the rebuilt rows.
        for o in runner.ops:
            if o.method == 'operations.get_by_key' and o.status == 'replied' \
                    and o.params:
                key = o.params.get('key')
                if o.ok is True:
                    verdict = 'admitted'
                elif o.code == 'NOT_FOUND':
                    verdict = 'not_admitted'
                else:
                    verdict = 'unknown'
                for row in runner.results:
                    if row['key'] == key:
                        row['result'] = verdict
        # Rebuild each running step's volatile detail from journal evidence —
        # send progress comes from the op ledger, never from re-entering the
        # step (re-entering would re-emit dangerous calls).
        for step in runner.steps:
            if step.status == 'running':
                runner._rehydrate(step, now_ms)
        runner._resumed = True
        return runner

    def _rehydrate(self, step: StepState, now_ms: int = 0):
        """Restore volatile per-step state after a resume. Every value here
        is derived from spec + journaled op rows — nothing is assumed."""
        spec = step.spec
        kind = step.kind
        step.detail.setdefault('rejoined', False)
        if kind in ('ping', 'control_send'):
            step.detail.setdefault('targets', self._send_targets(spec))
            step.detail.setdefault('duration_ms', spec.get('duration_ms'))
            # next_index = distinct planned indices consumed — 'send' rows
            # journal the real index (retries re-use one), skips consume
            # theirs too. A retry re-emit never advances the counter.
            consumed = {r['index'] for r in self.results
                        if r['step'] == step.index}
            step.next_index = max(consumed) + 1 if consumed else 0
            # A RATE_LIMITED reply's paced requeue is volatile — rebuild it
            # from the ledger so an interrupted deferral still re-sends under
            # its recorded index/key (due now; the deferral already elapsed).
            step.detail['retry_queue'] = [
                (r['index'], now_ms) for r in self.results
                if r['step'] == step.index and r['result'] == 'retry_pending']
            # The pacing anchor rides the first send's emit time — restored
            # from the ledger so the resumed grid stays absolute, not rebased.
            sent = [r['submit_ms'] for r in self.results
                    if r['step'] == step.index and r['submit_ms'] is not None]
            if sent:
                step.detail['t0_ms'] = min(sent)
            step.next_at_ms = 0
        elif kind in ('peer_send', 'soak'):
            self._rehydrate_bench(step, now_ms)
        elif kind in ('sequential_power_on', 'flash_provision'):
            targets = [self._target_id(t) for t in spec['targets']]
            done = set()
            for o in self.ops:
                if o.step != step.index or o.channel != 'device':
                    continue
                node = (o.params or {}).get('node')
                if o.status == 'replied' and o.ok is True and node:
                    done.add(node)
            step.detail['targets_left'] = [t for t in targets if t not in done]
            if kind == 'sequential_power_on':
                step.detail.setdefault('settle_ms', spec.get('settle_ms', 0))
                step.next_at_ms = 0
        elif kind == 'reset_rejoin':
            target = spec['target']
            step.detail.setdefault('target', self._target_id(
                target[0] if isinstance(target, list) else target))
            for o in self.ops:
                if o.step != step.index:
                    continue
                if o.method == 'reset' and o.status == 'replied' and o.ok is True:
                    step.detail['reset_done'] = o.reply_ms
                elif o.method == 'members.get' and o.status == 'replied' \
                        and o.ok is True and 'baseline' not in step.detail:
                    member = (o.result or {}).get('member') or {}
                    step.detail['baseline'] = {
                        'confirmed_ms': member.get('confirmed_ms'),
                        'last_seen_ms': member.get('last_seen_ms')}
            # Baseline taken but no reset op ever journaled → the call never
            # left the runner (journal-first emit), so emitting it now is a
            # first send, not a retry.
            if 'baseline' in step.detail and not any(
                    o.step == step.index and o.method == 'reset'
                    for o in self.ops):
                self._emit('device', 'reset',
                           {'node': step.detail['target']}, step, now_ms)
        elif kind == 'gateway_join':
            gateway = spec['gateway']
            step.detail.setdefault('gateway', self._target_id(
                gateway[0] if isinstance(gateway, list) else gateway))
        elif kind == 'formation_wait':
            step.detail.setdefault('count', spec['count'])
        # Crash window: the 'running' step row journaled but zero ops did —
        # journal-first emit means nothing ever left the runner, so a full
        # step re-enter is a first send, never a re-drive of proven work.
        if not any(o.step == step.index for o in self.ops):
            step.detail = {k: v for k, v in step.detail.items()
                           if k in ('rejoined',)}
            self._step_enter(step, now_ms)

    def _rehydrate_bench(self, step: StepState, now_ms: int):
        """Rebuild a running bench step's volatile state from journaled ops —
        per run_uuid, in issue order. Replied ops carry their decoded result
        on the journal row, so boots/counters survive a restart; a command
        that is still 'sent' leaves its phase pending for reconcile."""
        spec = step.spec
        pairs = [(self._target_id(p[0]), self._target_id(p[1]))
                 for p in spec.get('pairs', [])]
        bench = {'pairs': pairs, 'pair_i': 0, 'runs': [], 'gen': None}
        if step.kind == 'soak':
            bench['pair_share_ms'] = max(1, spec['duration_ms'] // max(1, len(pairs)))
            bench['pair_end_ms'] = None
            bench['interval'] = 0
            bench['ended'] = False
            bench['max_data_messages'] = spec.get('max_data_messages')
            bench['accum'] = {'planned': 0, 'submitted': 0, 'admitted': 0,
                              'delivered': 0, 'failed': 0, 'unknown': 0,
                              'dst_unique': 0, 'dst_duplicates': 0}
        step.detail['bench'] = bench
        count_default = spec.get('count') or min(
            GEN_MAX_COUNT, max(1, GEN_MAX_RUN_MS // spec['interval_ms']))
        # Group the step's bench ops by run uuid in issue order — each run is
        # one pair's (or one soak interval's) command sequence.
        runs: dict[str, dict] = {}
        order = []
        for o in self.ops:
            if o.step != step.index or o.channel != 'bench':
                continue
            p = o.params or {}
            run_uuid = p.get('run')
            if not isinstance(run_uuid, str):
                continue
            if run_uuid not in runs:
                # A run belongs to the pair its commands address — first op's
                # node is the source (hellos/start), later hellos/count_get
                # name the destination.
                pair_i = next((i for i, (s, d) in enumerate(pairs)
                               if s.lower() == str(p.get('node', '')).lower()
                               or d.lower() == str(p.get('node', '')).lower()), 0)
                runs[run_uuid] = {'run': run_uuid, 'seq': 0, 'phase': 'hello_src',
                                  'pair_i': pair_i, 'interval': 0,
                                  'src_boot': None, 'dst_boot': None,
                                  'pending': None, 'attempts': 0,
                                  'poll_misses': 0, 'last_poll_ms': 0,
                                  'last_status': None, 'dst_count': None,
                                  'count': count_default, 'deadline_ms': None,
                                  'closed': None}
                order.append(run_uuid)
                if step.kind == 'soak':
                    bench['interval'] += 1
                    runs[run_uuid]['interval'] = bench['interval']
            gen = runs[run_uuid]
            if not isinstance(p.get('seq'), int):
                continue
            if o.status == 'sent':
                # In-flight at crash: pending reuse keeps its (run, seq) so a
                # reconcile re-issue dedups inside the device command log.
                gen['seq'] = p['seq']
                gen['pending'] = {'method': o.method, **p}
                continue
            gen['seq'] = max(gen['seq'], p['seq'])
            gen['pending'] = None
            result = o.result if isinstance(o.result, dict) else None
            if o.status == 'replied' and o.ok is True and result is not None:
                src, dst = pairs[gen['pair_i']]
                node = str(p.get('node', '')).lower()
                if o.method == 'hello':
                    if node == src.lower():
                        gen['src_boot'] = result.get('boot_incarnation')
                        if gen['phase'] == 'hello_src':
                            gen['phase'] = 'hello_dst'
                    elif node == dst.lower():
                        gen['dst_boot'] = result.get('boot_incarnation')
                        if gen['phase'] in ('hello_src', 'hello_dst'):
                            gen['phase'] = 'start'
                elif o.method == 'peer_send_start':
                    gen['last_status'] = result
                    code = result.get('result')
                    if code in (rlb1.PS_STARTED, rlb1.PS_DUPLICATE):
                        gen['phase'] = 'running'
                    elif code == rlb1.PS_BUSY:
                        gen['closed'] = 'busy'
                    else:
                        gen['closed'] = 'refused'
                        gen['reason'] = peer_send_result_name(code)
                elif o.method in ('peer_send_status', 'peer_send_stop'):
                    gen['last_status'] = result
                    state = result.get('state')
                    if state in rlb1.GEN_TERMINAL or state == rlb1.GEN_IDLE \
                            or result.get('result') in (rlb1.PS_STOPPED,
                                                        rlb1.PS_NOT_RUNNING):
                        gen['phase'] = 'count_dst'
                elif o.method == 'count_get':
                    gen['dst_count'] = result
                    status = gen.get('last_status') or {}
                    gen['closed'] = gen_state_name(status.get('state'))
            elif o.status == 'replied' and o.ok is not True:
                # A refused/missed command mid-run: the run's evidence is no
                # longer provable — close it unknown (the live path would
                # have retried; on resume the miss stands once).
                if gen['closed'] is None:
                    gen['closed'] = 'unknown'
                    gen['reason'] = f'resumed:{o.code or "unreplied"}'
        # Fold closed runs into evidence; reopen the live tail.
        for run_uuid in order:
            gen = runs[run_uuid]
            if gen['closed'] is None:
                bench['pair_i'] = gen['pair_i']
                if step.kind == 'soak':
                    bench['interval'] = gen['interval']
                bench['gen'] = gen
                # A run reopened mid-'running' keeps polling; its deadline is
                # recomputed on the next emit.
                continue
            bench['pair_i'] = gen['pair_i'] + (0 if step.kind == 'soak' else 1)
            status = gen.get('last_status')
            row = {'pair': gen['pair_i'], 'interval': gen['interval'],
                   'run': gen['run'], 'outcome': gen['closed'],
                   'reason': gen.get('reason'),
                   'src_boot': gen.get('src_boot'), 'dst_boot': gen.get('dst_boot'),
                   'status': status, 'dst_count': gen.get('dst_count'),
                   'dst_unobserved': gen['dst_count'] is None}
            bench['runs'].append(row)
            if step.kind == 'soak':
                accum = bench['accum']
                for name in ('planned', 'submitted', 'admitted', 'delivered',
                             'failed', 'unknown'):
                    accum[name] += (status or {}).get(name, 0)
                dst_count = gen.get('dst_count') or {}
                accum['dst_unique'] += dst_count.get('unique_packets', 0)
                accum['dst_duplicates'] += dst_count.get('duplicates', 0)

    # -- plumbing --------------------------------------------------------------

    def _target_id(self, t) -> str:
        return t.lower() if _is_hex_id(t) else self.aliases.get(t.lower(), t.lower())

    def _emit(self, channel, method, params, step: StepState, now_ms,
              idempotency_key=None) -> Call:
        """Journal the op BEFORE the call leaves — reconcile-able by construction."""
        self.tag_counter += 1
        tag = f'{self.journal.run_id[:8]}-{self.tag_counter}'
        if self._last_emit_ms is not None and now_ms - self._last_emit_ms > 30_000:
            self.gap(now_ms, f'{now_ms - self._last_emit_ms}ms without runner output',
                     self._last_emit_ms)
        self._last_emit_ms = now_ms
        if channel == 'bench':
            # The op tag salts the bench submit key — each attempt is a
            # distinct host operation while the device still dedups by
            # (run, seq) inside the frame.
            params = {'op_tag': tag, **params}
        op = Op(tag=tag, step=step.index, channel=channel, method=method,
                sent_ms=now_ms, idempotency_key=idempotency_key,
                params=dict(params))
        self.ops.append(op)
        self.outstanding[tag] = op
        self.journal.record({'type': 'op', 'tag': tag, 'step': step.index,
                             'channel': channel, 'method': method,
                             'params': params if channel == 'api1' else {'op': method, **params},
                             'sent_ms': now_ms, 'status': 'sent',
                             'idempotency_key': idempotency_key})
        call = Call(tag=tag, channel=channel, method=method, params=params,
                    step=step.index, idempotency_key=idempotency_key)
        self._ready.append(call)
        return call

    def gap(self, now_ms: int, reason: str, from_ms: int):
        """Capture gaps are recorded, never smoothed over (D12)."""
        entry = {'type': 'gap', 'ms': now_ms, 'from_ms': from_ms, 'reason': reason}
        self.gaps.append(entry)
        self.journal.record(entry)

    def _step_done(self, step: StepState, now_ms: int, status='done', **detail):
        # A late reply for an already-settled step is recorded as an op row
        # but may NOT rewrite the step's verdict — evidence only accrues.
        if step.status not in ('pending', 'running'):
            return
        step.status = status
        step.ended_ms = now_ms
        step.detail.update(detail)
        self.journal.record({'type': 'step', 'index': step.index, 'id': step.id,
                             'kind': step.kind, 'status': status,
                             'started_ms': step.started_ms, 'ended_ms': now_ms,
                             'detail': detail})
        # A failed non-optional step or an incomplete one drains the run:
        # in-flight ops still reconcile, then the terminal state lands —
        # nothing is abandoned mid-flight with an unrecorded fate.
        if status == 'failed' and not step.spec.get('optional'):
            self.abort(f'step {step.id} failed')
        elif status == 'incomplete':
            self.abort(f'step {step.id} incomplete')
        else:
            self._advance(now_ms)

    def _advance(self, now_ms: int):
        while self.step_index < len(self.steps):
            nxt = self.steps[self.step_index]
            if nxt.status in ('pending', 'running'):
                return
            self.step_index += 1
        if self.step_index >= len(self.steps):
            self.state = STATE_DRAINING
            self.journal.set_state(STATE_DRAINING)

    def _finish(self, state: str):
        if self.state in STATE_TERMINAL:
            return
        self.state = state
        self.journal.set_state(state)

    def abort(self, reason='user stop'):
        if self.state in STATE_TERMINAL:
            return
        self.stop_reason = reason
        self.journal.record({'type': 'stop', 'reason': reason})
        now_ms = self._last_emit_ms or 0
        # Settle every unsettled step: pending ones are recorded as skipped
        # (never ran), a running one becomes incomplete — the run's tail is
        # always explainable, never a silent truncation.
        for s in self.steps:
            if s.status == 'pending':
                s.status = 'skipped'
                self.journal.record({'type': 'step', 'index': s.index, 'id': s.id,
                                     'kind': s.kind, 'status': 'skipped',
                                     'detail': {'reason': 'run_aborted'}})
            elif s.status == 'running':
                s.status = 'incomplete'
                s.ended_ms = now_ms
                self.journal.record({'type': 'step', 'index': s.index, 'id': s.id,
                                     'kind': s.kind, 'status': 'incomplete',
                                     'started_ms': s.started_ms, 'ended_ms': now_ms,
                                     'detail': {'reason': 'run_aborted'}})
        self.step_index = len(self.steps)
        self.state = STATE_DRAINING
        self.journal.set_state(STATE_DRAINING)

    @property
    def finished(self):
        return self.state in STATE_TERMINAL and not self.outstanding

    # -- main loop -------------------------------------------------------------

    def due(self, now_ms: int) -> list[Call]:
        # A stalled host leaves a gap in the record — measured on the tick,
        # not on emits, so a quiet drain period still shows the silence.
        if self._last_tick_ms is not None and now_ms - self._last_tick_ms > 30_000:
            self.gap(now_ms, f'{now_ms - self._last_tick_ms}ms between runner ticks',
                     self._last_tick_ms)
        self._last_tick_ms = now_ms
        # _emit queues calls on _ready; step logic and reply reconciliation
        # may both emit during this tick, so drain at the end.
        if self.state in STATE_TERMINAL:
            calls, self._ready = self._ready, []
            return calls
        if self.state == 'Armed':
            self.state = STATE_RUNNING
            self.journal.set_state(STATE_RUNNING)
        # Reply timeouts: a silent transport marks the op 'lost'; the owning
        # step reconciles (submit → get_by_key, site verbs → same-key re-issue).
        for tag, op in list(self.outstanding.items()):
            if op.status == 'sent' and now_ms - op.sent_ms > REPLY_TIMEOUT_MS:
                self._reconcile(op, now_ms)
        # In Draining no step may enter — outstanding ops still reconcile and
        # settle, then the terminal state lands.
        step = None if self.state == STATE_DRAINING else self._current()
        if step is not None:
            if step.status == 'pending':
                step.status = 'running'
                step.started_ms = now_ms
                step.deadline_ms = now_ms + step.spec.get('timeout_ms', DEFAULT_STEP_TIMEOUT_MS)
                self.journal.record({'type': 'step', 'index': step.index, 'id': step.id,
                                     'kind': step.kind, 'status': 'running',
                                     'started_ms': now_ms})
                self._step_enter(step, now_ms)
            elif step.status == 'running':
                if step.deadline_ms is not None and now_ms > step.deadline_ms:
                    self._step_timeout(step, now_ms)
                else:
                    self._step_poll(step, now_ms)
        self._drain_check(now_ms)
        calls, self._ready = self._ready, []
        return calls

    def _current(self) -> StepState | None:
        while self.step_index < len(self.steps):
            step = self.steps[self.step_index]
            if step.status == 'pending':
                return step
            if step.status == 'running':
                return step
            self.step_index += 1
        return None

    def _drain_check(self, now_ms: int):
        if self.step_index < len(self.steps) or self.outstanding:
            return
        # Order matters: evidence loss beats a plain failure beats a stop.
        if any(s.status == 'incomplete' for s in self.steps):
            self._finish('Incomplete')
        elif any(s.status == 'failed' for s in self.steps):
            self._finish('Failed')
        elif self.stop_reason:
            self._finish('Aborted')
        else:
            self._finish('Completed')

    # -- step dispatch ----------------------------------------------------------

    def _step_enter(self, step: StepState, now_ms: int):
        kind = step.kind
        spec = step.spec
        if kind == 'record_start':
            # Local boundary: caller opens a capture session at spec['path'].
            self._emit('local', 'record_start',
                                    {'path': spec.get('path'), 'label': spec.get('label')},
                                    step, now_ms)
        elif kind == 'flash_provision':
            step.detail['targets_left'] = [self._target_id(t) for t in spec['targets']]
            self._next_provision(step, now_ms)
        elif kind == 'gateway_join':
            step.detail['gateway'] = self._target_id(spec['gateway'][0] if isinstance(
                spec['gateway'], list) else spec['gateway'])
            self._emit('api1', 'members.list', {}, step, now_ms)
        elif kind == 'join_policy':
            self._emit('api1', 'join.policy.set', dict(spec['policy']), step, now_ms)
        elif kind == 'sequential_power_on':
            step.detail['targets_left'] = [self._target_id(t) for t in spec['targets']]
            step.detail['settle_ms'] = spec.get('settle_ms', 0)
            step.next_at_ms = now_ms
        elif kind == 'formation_wait':
            step.detail['count'] = spec['count']
            step.detail['last_poll_ms'] = 0
            step.next_at_ms = now_ms
        elif kind == 'rollcall':
            method = {'start': 'lab.rollcall.start', 'stop': 'lab.rollcall.stop',
                      'status': 'lab.rollcall.status'}[spec['action']]
            params = {'network': self.network}
            if spec.get('group'):
                params['group'] = spec['group']
            self._emit('api1', method, params, step, now_ms)
        elif kind in ('ping', 'control_send'):
            step.detail['targets'] = self._send_targets(spec)
            step.next_index = 0
            step.next_at_ms = now_ms
            step.detail['duration_ms'] = spec.get('duration_ms')
            step.detail['deadline'] = step.deadline_ms
            self._ensure_epoch(step, now_ms)
        elif kind in ('peer_send', 'soak'):
            # Device-generated traffic: the runner only issues the bounded
            # RLB1 commands; the device owns the data path. `bench` state is
            # rebuilt from journaled ops on resume — it is a cache, never a
            # source of truth.
            pairs = [(self._target_id(p[0]), self._target_id(p[1]))
                     for p in spec.get('pairs', [])]
            bench = {'pairs': pairs, 'pair_i': 0, 'runs': [], 'gen': None}
            if kind == 'soak':
                share = spec['duration_ms'] // max(1, len(pairs))
                bench['pair_share_ms'] = max(1, share)
                bench['pair_end_ms'] = None
                bench['interval'] = 0
                bench['ended'] = False
                bench['max_data_messages'] = spec.get('max_data_messages')
                bench['accum'] = {'planned': 0, 'submitted': 0, 'admitted': 0,
                                  'delivered': 0, 'failed': 0, 'unknown': 0,
                                  'dst_unique': 0, 'dst_duplicates': 0}
            step.detail['bench'] = bench
        elif kind == 'drain':
            pass                                    # _step_poll waits outstanding
        elif kind == 'reset_rejoin':
            target = self._target_id(spec['target'][0] if isinstance(spec['target'], list)
                                     else spec['target'])
            step.detail['target'] = target
            # Baseline first: a member row exists *before* the reset too, so
            # rejoin evidence is a changed members.get timestamp — confirmed_ms
            # or last_seen_ms advancing past the baseline.
            self._emit('api1', 'members.get', {'device_id': target}, step, now_ms)
        elif kind == 'exclusion':
            target = self._target_id(spec['target'][0] if isinstance(spec['target'], list)
                                     else spec['target'])
            step.detail['target'] = target
            idem = f'{self.journal.run_id}-excl-{step.index}'
            step.detail['idempotency_key'] = idem
            params = {'device_id': target, 'idempotency_key': idem,
                      'reason': spec['reason'],
                      'expected_generation': spec['expected_generation']}
            self._emit('api1', 'membership.revoke', params, step, now_ms,
                                    idempotency_key=idem)
        elif kind == 'gk_rotate':
            idem = f'{self.journal.run_id}-gk-{step.index}'
            step.detail['idempotency_key'] = idem
            self._emit('api1', 'group_keys.rotate',
                                    {'expected_active_epoch': spec['expected_active_epoch'],
                                     'idempotency_key': idem}, step, now_ms,
                                    idempotency_key=idem)
        elif kind == 'cutover':
            idem = f'{self.journal.run_id}-cutover-{step.index}'
            step.detail['idempotency_key'] = idem
            self._emit('api1', 'membership.cutover',
                                    {'expected_site_epoch': spec['expected_site_epoch'],
                                     'next_site_cert': spec['next_site_cert'],
                                     'idempotency_key': idem}, step, now_ms,
                                    idempotency_key=idem)
        elif kind == 'report':
            self._emit('local', 'report',
                                    {'formats': spec.get('formats', ['json']),
                                     'path': spec.get('path')}, step, now_ms)

    def _send_targets(self, spec) -> list:
        if spec['kind'] == 'ping':
            to = spec['to']
            return [self._target_id(t) for t in (to if isinstance(to, list) else [to])]
        if spec['kind'] == 'control_send':
            t = spec['target']
            return [self._target_id(t if not isinstance(t, list) else t[0])]
        return [self._target_id(t) for t in spec.get('targets', [])]

    def _ensure_epoch(self, step: StepState, now_ms: int):
        if self.epoch is None and not self.epoch_pending and now_ms >= self.epoch_retry_at_ms:
            self.epoch_pending = True
            self._emit('api1', 'operations.open_epoch',
                                    {'network': self.network}, step, now_ms)

    def _step_poll(self, step: StepState, now_ms: int):
        kind = step.kind
        if kind == 'sequential_power_on':
            left = step.detail['targets_left']
            if not left:
                # The last power_on must have answered before the step ends —
                # an unacknowledged board is not "powered".
                if not any(o.step == step.index and o.channel == 'device'
                           and o.status == 'sent'
                           for o in self.outstanding.values()):
                    self._step_done(step, now_ms,
                                    powered=step.detail.get('powered'))
            elif now_ms >= step.next_at_ms and \
                    not any(o.channel == 'device' for o in self.outstanding.values()):
                target = left[0]
                self._emit('device', 'power_on', {'node': target}, step, now_ms)
                step.detail['targets_left'] = left[1:]
                step.next_at_ms = now_ms + step.detail['settle_ms']
        elif kind == 'formation_wait':
            if now_ms - step.detail.get('last_poll_ms', -POLL_MS) >= POLL_MS and \
                    not any(o.method == 'nodes.list' for o in self.outstanding.values()):
                step.detail['last_poll_ms'] = now_ms
                step.detail['seen'] = 0
                self._emit('api1', 'nodes.list', {'limit': 128}, step, now_ms)
        elif kind == 'gateway_join':
            if now_ms - step.detail.get('last_poll_ms', -POLL_MS) >= POLL_MS and \
                    not any(o.method == 'members.list' for o in self.outstanding.values()):
                step.detail['last_poll_ms'] = now_ms
                self._emit('api1', 'members.list', {}, step, now_ms)
        elif kind in ('ping', 'control_send'):
            self._send_poll(step, now_ms)
        elif kind in ('peer_send', 'soak'):
            self._bench_poll(step, now_ms)
        elif kind == 'drain':
            if not self.outstanding:
                self._step_done(step, now_ms)
        elif kind == 'reset_rejoin':
            if step.detail.get('rejoined'):
                self._step_done(step, now_ms)
            elif step.detail.get('reset_done') and \
                    not any(o.method == 'members.get' for o in self.outstanding.values()) and \
                    now_ms - step.detail.get('last_poll_ms', -POLL_MS) >= POLL_MS:
                step.detail['last_poll_ms'] = now_ms
                self._emit('api1', 'members.get',
                           {'device_id': step.detail['target']}, step, now_ms)

    def _send_poll(self, step: StepState, now_ms: int):
        """Admission-charged send pacing: one submit in flight per step, the
        per-step interval honored, the inflight/run-window caps enforced."""
        if self.epoch is None:
            self._ensure_epoch(step, now_ms)
            return
        spec = step.spec
        targets = step.detail['targets']
        if not targets:
            self._step_done(step, now_ms, 'failed', reason='no_targets')
            return
        duration = step.detail.get('duration_ms')
        if duration is not None and now_ms - step.started_ms >= duration:
            self._step_done(step, now_ms, sends=step.next_index)
            return
        count = spec.get('count')               # duration steps have no count
        interval = spec.get('interval_ms') or spec.get('period_ms') or 1000
        if spec['kind'] == 'soak':
            # per_node interval ÷ target count = the global emit spacing.
            interval = max(50, (spec.get('per_node_interval_ms') or 1000)
                           // max(1, len(targets)))
        # Client discipline: capacity.get's bench block wins over plan
        # limits; the tighter of the two is enforced.
        client = (self.capacity.get('admission') or {}).get('client') or {}
        inflight = min(self.limits.get('inflight_max', BENCH_INFLIGHT_MAX),
                       client.get('inflight_max', BENCH_INFLIGHT_MAX))
        if len([o for o in self.outstanding.values() if o.method == 'messages.submit'
                and o.status == 'sent']) >= inflight:
            return
        # Run window: never more than N submits in any rolling window
        # (client discipline published by capacity.get).
        window_calls = client.get('run_window_calls', BENCH_RUN_WINDOW_CALLS)
        window_ms = client.get('run_window_ms', BENCH_RUN_WINDOW_MS)
        recent = sum(1 for o in self.ops
                     if o.method == 'messages.submit' and o.sent_ms >= now_ms - window_ms)
        if recent >= window_calls:
            return
        # A rate-limited send goes first once its retry_after window passes —
        # same planned index, same deterministic key.
        retry = step.detail.setdefault('retry_queue', [])
        retry_due = bool(retry) and now_ms >= min(e[1] for e in retry)
        total = count * len(targets) if count is not None else None
        if not retry_due and total is not None and step.next_index >= total \
                and not retry:
            # Every send issued — wait for the ledger to settle below.
            if not any(o.step == step.index and o.status == 'sent'
                       for o in self.outstanding.values()):
                self._step_done(step, now_ms, sends=step.next_index)
            return
        # Absolute pacing (§603): t0 + index×interval. A slot the runner fell
        # a full interval behind on is recorded skipped — never a catch-up burst.
        t0 = step.detail.setdefault('t0_ms', now_ms)
        index = step.next_index
        planned_ms = t0 + index * interval
        if not retry_due and (now_ms < planned_ms
                              or (total is not None and index >= total)):
            return
        if not retry_due and now_ms - planned_ms > max(interval, 500):
            self.results.append({'step': step.index, 'index': index,
                                 'target': targets[index % len(targets)],
                                 'key': None, 'planned_ms': planned_ms,
                                 'submit_ms': None, 'result': 'skipped_late'})
            self.journal.record({'type': 'skip', 'step': step.index,
                                 'index': index, 'planned_ms': planned_ms,
                                 'ms': now_ms})
            step.next_index += 1
            return
        if retry_due:
            earliest = min(range(len(retry)), key=lambda i: retry[i][1])
            index, _ = retry.pop(earliest)
            target = targets[index % len(targets)]
            row = next((r for r in reversed(self.results)
                        if r['step'] == step.index and r['index'] == index), None)
            if row is not None:
                row['submit_ms'] = now_ms
                row['result'] = 'submitted'
        else:
            target = targets[index % len(targets)]
            step.next_index += 1
            self.results.append({'step': step.index, 'index': index, 'target': target,
                                 'key': hashlib.sha256(
                                     f'{self.journal.run_id}:{step.index}:{index}'
                                     .encode()).hexdigest()[:32],
                                 'planned_ms': planned_ms,
                                 'submit_ms': now_ms,
                                 'late_ms': now_ms - planned_ms,
                                 'result': 'submitted'})
        key = hashlib.sha256(
            f'{self.journal.run_id}:{step.index}:{index}'.encode()).hexdigest()[:32]
        self.journal.record({'type': 'send', 'step': step.index,
                             'index': index, 'key': key, 'target': target,
                             'ms': now_ms})
        options = {'storage': 'RAM_ONLY',
                   'delivery': spec.get('delivery', 'BEST_EFFORT'),
                   'ttl_ms': spec.get('ttl_ms', 30_000)}
        if spec['kind'] == 'control_send' or spec.get('queue_mode') == 'LATEST_PER_DESTINATION':
            options['queue_mode'] = 'LATEST_PER_DESTINATION'
        self._emit('api1', 'messages.submit', {
            'network': self.network, 'admission_epoch': self.epoch, 'key': key,
            'destination': {'kind': 'node', 'id': target},
            'payload_hex': self._payload(spec, index),
            'payload_len': spec.get('payload_len', 8),
            'options': options}, step, now_ms)

    @staticmethod
    def _payload(spec, index) -> str:
        body = hashlib.sha256(f'{index}'.encode()).digest()
        n = spec.get('payload_len', 8)
        return (body * (n // 32 + 1))[:n].hex()

    # -- bench device-generator steps (D10/D12) --------------------------------
    #
    # The runner never puts data-plane packets on the wire for peer_send/soak.
    # Per pair it runs one bounded generator run on the SOURCE bench node —
    # hello → hello → start → status polls → stop/count — then moves on. Every
    # RLB1 command is a journaled 'bench' op; a lost command re-issues under
    # the same (run_uuid, seq) so the device's command dedup never mints a
    # second run. A command that never produces evidence closes the run as
    # unknown — missing replies are never counted as success.
    #
    # gen phases: hello_src → hello_dst → start → running → (stop) → count_dst.
    # 'running' emits bounded status queries; every other phase emits exactly
    # one command, re-issued under the SAME seq on a transport miss.

    def _bench_poll(self, step: StepState, now_ms: int):
        bench = step.detail['bench']
        if any(o.step == step.index and o.channel == 'bench' and o.status == 'sent'
               for o in self.outstanding.values()):
            return                       # one command in flight — replies stay paired
        gen = bench['gen']
        if gen is None:
            gen = self._bench_open_run(step, now_ms)
            if gen is None:
                return                   # _bench_finish already settled the step
        self._bench_emit_phase(step, gen, now_ms)

    def _bench_open_run(self, step: StepState, now_ms: int):
        """Pick the next pair/interval and open its run; returns None when the
        step has no work left (and settles it)."""
        bench = step.detail['bench']
        pairs = bench['pairs']
        if not pairs:
            self._step_done(step, now_ms, 'failed', reason='no_pairs')
            return None
        while bench['pair_i'] < len(pairs):
            if step.kind == 'soak':
                pair_end = bench['pair_end_ms']
                if pair_end is None:
                    bench['pair_end_ms'] = now_ms + bench['pair_share_ms']
                elif now_ms >= pair_end or bench.get('ended'):
                    bench['pair_i'] += 1
                    bench['pair_end_ms'] = None
                    continue
                bench['interval'] += 1
            elif bench.get('pair_done'):
                bench['pair_i'] += 1
                bench['pair_done'] = False
                continue
            gen = self._bench_new_gen(step, bench['pair_i'],
                                      bench.get('interval', 0))
            bench['gen'] = gen
            return gen
        self._bench_finish(step, now_ms)
        return None

    def _bench_new_gen(self, step: StepState, pair_i: int, interval: int) -> dict:
        run = hashlib.sha256(
            f'{self.journal.run_id}:{step.index}:{pair_i}:{interval}'
            .encode()).digest()[:16].hex()
        spec = step.spec
        interval_ms = spec['interval_ms']
        count = spec.get('count') or min(
            GEN_MAX_COUNT, max(1, GEN_MAX_RUN_MS // interval_ms))
        return {'run': run, 'seq': 0, 'phase': 'hello_src', 'pair_i': pair_i,
                'interval': interval, 'src_boot': None, 'dst_boot': None,
                'pending': None, 'attempts': 0, 'poll_misses': 0,
                'last_poll_ms': 0, 'last_status': None, 'dst_count': None,
                'count': count,
                'deadline_ms': None}

    def _bench_emit_phase(self, step: StepState, gen: dict, now_ms: int):
        bench = step.detail['bench']
        phase = gen['phase']
        src, dst = bench['pairs'][gen['pair_i']]
        if phase == 'running':
            spec = step.spec
            if step.kind == 'soak' and not gen.get('stop_sent') and \
                    (bench.get('ended') or
                     (bench.get('pair_end_ms') is not None
                      and now_ms >= bench['pair_end_ms'])):
                # The bounded interval ended — drain explicitly; the device
                # closes the run as STOPPED, never by silence.
                gen['stop_sent'] = True
                gen['phase'] = 'stop'
                self._bench_emit_phase(step, gen, now_ms)
                return
            if gen['deadline_ms'] is None:
                # Nominal run span + the longest packet lifetime + slack —
                # past this an unpolled run is unverifiable.
                gen['deadline_ms'] = now_ms + \
                    bench_run_ms(gen['count'], spec['interval_ms']) + \
                    spec.get('ttl_ms', GEN_TTL_MAX_MS) + 10_000
            if now_ms >= gen['deadline_ms']:
                self._bench_close_run(step, gen, 'unknown', now_ms,
                                      reason='status_deadline')
                return
            if now_ms - gen['last_poll_ms'] < BENCH_STATUS_POLL_MS:
                return
            gen['last_poll_ms'] = now_ms
            gen['seq'] += 1
            self._emit('bench', 'peer_send_status',
                       {'node': src, 'run': gen['run'], 'seq': gen['seq']},
                       step, now_ms)
            return
        if gen['pending'] is None:
            gen['seq'] += 1
            gen['pending'] = self._bench_command(step, gen, phase, src, dst)
        params = dict(gen['pending'])
        method = params.pop('method')
        self._emit('bench', method, params, step, now_ms)

    def _bench_command(self, step: StepState, gen: dict, phase: str,
                       src: str, dst: str) -> dict:
        spec = step.spec
        params = {'node': src, 'run': gen['run'], 'seq': gen['seq']}
        if phase == 'hello_src':
            params['method'] = 'hello'
        elif phase == 'hello_dst':
            params['method'] = 'hello'
            params['node'] = dst
        elif phase == 'start':
            params.update({'method': 'peer_send_start',
                           'expected_boot': gen['src_boot'] or 0,
                           'expected_dest_boot': gen['dst_boot'] or 0,
                           'destination': dst,
                           'sequence_begin': 1,
                           'count': gen['count'],
                           'payload_len': spec.get('payload_len', GEN_PAYLOAD_MIN),
                           'seed': spec.get('seed', 0),
                           'interval_ms': spec['interval_ms'],
                           'ttl_ms': spec.get('ttl_ms', GEN_TTL_MAX_MS),
                           'max_inflight': 1})
        elif phase == 'stop':
            params.update({'method': 'peer_send_stop',
                           'expected_boot': gen['src_boot'] or 0})
        elif phase == 'count_dst':
            params.update({'method': 'count_get', 'node': dst})
        else:
            raise ScenarioError('bad_phase', phase)
        return params

    def _bench_reply(self, step: StepState, op: Op, result: dict, now_ms: int):
        """A bench op answered — advance the run's phase on the reply's own
        evidence, keyed by (run, seq) so a reconciled re-issue lands in the
        same slot."""
        bench = step.detail['bench']
        gen = bench.get('gen')
        params = op.params or {}
        if gen is None or params.get('run') != gen['run'] \
                or params.get('seq') != gen['seq']:
            return                       # stale/superseded — journaled, unused
        gen['pending'] = None
        gen['attempts'] = 0
        method = op.method
        if method == 'hello':
            boot = result.get('boot_incarnation')
            src, dst = bench['pairs'][gen['pair_i']]
            if params.get('node', '').lower() == src.lower():
                gen['src_boot'] = boot
                gen['phase'] = 'hello_dst'
            else:
                gen['dst_boot'] = boot
                gen['phase'] = 'start'
        elif method == 'peer_send_start':
            gen['last_status'] = result
            code = result.get('result')
            if code in (rlb1.PS_STARTED, rlb1.PS_DUPLICATE):
                # STARTED = accepted; DUPLICATE = a lost first reply —
                # dedup proved this (run,seq) is the already-running one.
                gen['phase'] = 'running'
                gen['last_poll_ms'] = now_ms
            elif code == rlb1.PS_BUSY:
                self._bench_close_run(step, gen, 'busy', now_ms)
            else:                        # STALE_BOOT / INVALID — a refusal
                self._bench_close_run(
                    step, gen, 'refused', now_ms,
                    reason=peer_send_result_name(code))
        elif method in ('peer_send_status', 'peer_send_stop'):
            gen['last_status'] = result
            gen['poll_misses'] = 0
            state = result.get('state')
            if state in rlb1.GEN_TERMINAL or state == rlb1.GEN_IDLE \
                    or result.get('result') in (rlb1.PS_STOPPED, rlb1.PS_NOT_RUNNING):
                gen['phase'] = 'count_dst'
            elif method == 'peer_send_status' and step.kind == 'soak' \
                    and bench.get('max_data_messages') is not None:
                # The soak's data budget is spent — drain the live run
                # explicitly rather than letting it run to its own bound.
                if bench['accum']['submitted'] + \
                        result.get('submitted', 0) >= \
                        bench['max_data_messages']:
                    bench['ended'] = True
        elif method == 'count_get':
            gen['dst_count'] = result
            status = gen.get('last_status') or {}
            self._bench_close_run(
                step, gen, gen_state_name(status.get('state')), now_ms)

    def _bench_failed(self, step: StepState, op: Op, code: str, now_ms: int):
        bench = step.detail['bench']
        gen = bench.get('gen')
        params = op.params or {}
        if gen is None or params.get('run') != gen['run'] \
                or params.get('seq') != gen['seq']:
            return                       # superseded — the journaled row stands
        if code in ('INVALID_ARGUMENT', 'BENCH_DECODE', 'UNKNOWN_BENCH_OP'):
            # A caller-side bug or an unparseable reply — not recoverable by
            # re-issue; the step fails honestly.
            self._step_done(step, now_ms, 'failed',
                            reason=f'bench:{code}', op=op.tag)
            return
        gen['attempts'] += 1
        if gen['phase'] == 'running':
            gen['poll_misses'] += 1
            if gen['poll_misses'] < 3:
                return                   # bounded interval: next poll retries
            self._bench_close_run(step, gen, 'unknown', now_ms,
                                  reason='status_unanswered')
            return
        if gen['attempts'] < BENCH_PHASE_ATTEMPTS:
            return                       # same-(run,seq) re-issue on next poll
        if gen['phase'] == 'count_dst':
            # The source's status evidence still stands; only the receiver
            # side is unobserved.
            status = gen.get('last_status') or {}
            self._bench_close_run(
                step, gen, gen_state_name(status.get('state')), now_ms,
                dst_unobserved=True)
            return
        self._bench_close_run(step, gen, 'unknown', now_ms,
                              reason=f'{gen["phase"]}:{code}')

    def _bench_close_run(self, step: StepState, gen: dict, outcome: str,
                         now_ms: int, reason: str | None = None,
                         dst_unobserved: bool = False):
        """Seal the run's evidence row and release the generator slot. The
        row records exactly what the device reported — source counters and
        receiver counters stay separate facts."""
        bench = step.detail['bench']
        status = gen.get('last_status')
        row = {'pair': gen['pair_i'], 'interval': gen['interval'],
               'run': gen['run'], 'outcome': outcome,
               'reason': reason,
               'src_boot': gen.get('src_boot'),
               'dst_boot': gen.get('dst_boot'),
               'status': status, 'dst_count': gen.get('dst_count'),
               'dst_unobserved': dst_unobserved}
        bench['runs'].append(row)
        if step.kind == 'soak':
            accum = bench['accum']
            for name in ('planned', 'submitted', 'admitted', 'delivered',
                         'failed', 'unknown'):
                accum[name] += (status or {}).get(name, 0)
            dst = gen.get('dst_count') or {}
            accum['dst_unique'] += dst.get('unique_packets', 0)
            accum['dst_duplicates'] += dst.get('duplicates', 0)
            if bench.get('max_data_messages') is not None and \
                    accum['submitted'] >= bench['max_data_messages']:
                bench['ended'] = True
        if step.kind == 'peer_send':
            # One bounded run per pair — closing it finishes the pair.
            bench['pair_done'] = True
        bench['gen'] = None

    def _bench_finish(self, step: StepState, now_ms: int):
        bench = step.detail['bench']
        runs = bench['runs']
        detail = {'bench_runs': runs, 'pairs': len(bench['pairs'])}
        if step.kind == 'soak':
            detail['accum'] = bench['accum']
            detail['intervals'] = len(runs)
        # Evidence rule: the step is 'done' only when every run reached a
        # device-terminal state. Refused/busy/unknown runs are evidence of a
        # run that never produced its data plane — the step is incomplete,
        # never a silent pass.
        terminal = {'complete', 'stopped', 'time_bound', 'peer_reset'}
        if runs and all(r['outcome'] in terminal for r in runs):
            self._step_done(step, now_ms, **detail)
        elif any(r['outcome'] == 'refused' for r in runs):
            reason = next(r['reason'] for r in runs if r['outcome'] == 'refused')
            self._step_done(step, now_ms, 'failed', reason=reason, **detail)
        else:
            self._step_done(step, now_ms, 'incomplete',
                            reason='runs_without_terminal_evidence', **detail)

    def _next_provision(self, step, now_ms):
        left = step.detail['targets_left']
        if not left:
            self._step_done(step, now_ms)
            return
        self._emit('device', 'provision',
                                {'node': left[0], 'bundle': step.spec['bundle']},
                                step, now_ms)
        step.detail['targets_left'] = left[1:]

    def _step_timeout(self, step: StepState, now_ms: int):
        # A dangerous step never takes an unconditional retry; it degrades
        # to incomplete so the next operation cannot ride unproven state.
        _, dangerous, _ = STEP_DEFS[step.kind]
        if dangerous:
            self._step_done(step, now_ms, 'incomplete', reason='timeout',
                            unreplied=[o.tag for o in self.outstanding.values()
                                       if o.step == step.index])
        elif step.spec.get('optional'):
            self._step_done(step, now_ms, 'skipped', reason='timeout')
        else:
            self._step_done(step, now_ms, 'failed', reason='timeout')

    # -- reply / reconcile --------------------------------------------------------

    def _reconcile(self, op: Op, now_ms: int):
        """A reply went missing. Reconcile by evidence: same-key lookup for
        submits, same-key re-issue for site verbs, device ops stay unprovable."""
        step = self.steps[op.step]
        if step.status not in ('pending', 'running'):
            # The owning step already settled (timeout→incomplete etc.) — the
            # op is abandoned, never re-issued against a finished step.
            op.status = 'abandoned'
            self.outstanding.pop(op.tag, None)
            self.journal.record({'type': 'op', 'tag': op.tag, 'step': op.step,
                                 'status': 'abandoned', 'ms': now_ms})
            return
        if op.channel == 'api1' and op.method == 'messages.submit':
            key = self._op_key(op)
            if key and self.epoch:
                op.status = 'lost'
                self._emit_reconcile('operations.get_by_key', {
                    'network': self.network, 'admission_epoch': self.epoch, 'key': key},
                    op, now_ms)
                return
        elif op.channel == 'api1' and op.idempotency_key:
            # Site verbs dedup on the recorded key — re-issue IS the reconcile.
            params = dict(self._op_params(op))
            self._emit_reconcile(op.method, params, op, now_ms,
                                 keep_key=op.idempotency_key)
            return
        elif op.channel == 'bench':
            # A bench command's identity is (run_uuid, seq) — re-issuing the
            # journaled params dedups inside the device command log exactly
            # like a site verb. One re-issue only: a second miss means the
            # evidence path is gone.
            if op.reconciles is None:
                params = dict(self._op_params(op))
                op.status = 'lost'
                self._emit_reconcile(op.method, params, op, now_ms)
                return
        op.status = 'lost'
        self.outstanding.pop(op.tag, None)
        self.journal.record({'type': 'op', 'tag': op.tag, 'step': op.step,
                             'status': 'lost', 'ms': now_ms})
        _, dangerous, _ = STEP_DEFS[step.kind]
        if dangerous:
            self._step_done(step, now_ms, 'incomplete', reason='unreconciled',
                            op=op.tag)

    def _emit_reconcile(self, method, params, op: Op, now_ms: int, keep_key=None) -> Call:
        tag = f'{self.journal.run_id[:8]}-r{op.tag.rsplit("-", 1)[-1]}'
        if op.channel == 'bench':
            # Fresh submit key — the daemon would otherwise dedup the retry
            # against the lost attempt and the device would never see it.
            params = {**params, 'op_tag': tag}
        reconciled = Op(tag=tag, step=op.step, channel=op.channel, method=method,
                        sent_ms=now_ms, status='sent', idempotency_key=keep_key,
                        params=dict(params), reconciles=op.tag)
        self.ops.append(reconciled)
        self.outstanding[tag] = reconciled
        self.journal.record({'type': 'op', 'tag': tag, 'step': op.step,
                             'channel': op.channel, 'method': method,
                             'params': params,
                             'sent_ms': now_ms, 'status': 'sent',
                             'reconciles': op.tag,
                             'idempotency_key': keep_key})
        op.status = 'reconciled'
        self.outstanding.pop(op.tag, None)
        call = Call(tag=tag, channel=op.channel, method=method, params=params,
                    step=op.step, idempotency_key=keep_key)
        self._ready.append(call)
        return call

    def _op_params(self, op: Op) -> dict:
        """The op's original request params — in-memory, else from its
        'sent' journal row (replied/lost transition rows carry no params)."""
        if op.params is not None:
            return dict(op.params)
        for entry in reversed(self.journal.entries):
            if entry.get('type') == 'op' and entry.get('tag') == op.tag \
                    and entry.get('params') is not None:
                return dict(entry['params'])
        return {}

    def _op_key(self, op: Op) -> str | None:
        return self._op_params(op).get('key')

    def on_reply(self, tag: str, reply, now_ms: int):
        op = self.outstanding.pop(tag, None)
        if op is None:
            # A reply for an unknown tag is still evidence — journal it so a
            # late answer to an abandoned op is never silently lost.
            self.journal.record({'type': 'late_reply', 'tag': tag, 'ms': now_ms,
                                 'ok': isinstance(reply, dict) and reply.get('ok') is True})
            return
        ok = isinstance(reply, dict) and reply.get('ok') is True
        result = reply.get('result') if ok else None
        error = reply.get('error', {}) if isinstance(reply, dict) else {}
        code = None if ok else (error.get('code') if isinstance(error, dict) else None) or \
            ('NO_REPLY' if reply is None else 'INVALID_REPLY')
        op.status = 'replied'
        op.reply_ms = now_ms
        op.ok = ok
        op.code = code
        op.result = result if isinstance(result, dict) else None
        record = {'type': 'op', 'tag': tag, 'step': op.step,
                  'status': 'replied', 'reply_ms': now_ms, 'ok': ok,
                  'code': code}
        if ok and (op.method == 'members.get' or op.channel == 'bench'):
            # The reset_rejoin baseline survives on the result — journal it so
            # a resume still compares against the pre-reset snapshot. Bench
            # replies carry the device counters the resume re-folds.
            record['result'] = op.result
        self.journal.record(record)
        step = self.steps[op.step]
        if not ok:
            self._op_failed(step, op, code, error, now_ms)
            return
        self._op_done(step, op, result, now_ms)

    def _op_failed(self, step: StepState, op: Op, code: str, error, now_ms: int):
        _, dangerous, _ = STEP_DEFS[step.kind]
        if op.method == 'operations.open_epoch':
            self.epoch_pending = False
            if code == 'RATE_LIMITED':
                detail = error.get('detail') if isinstance(error, dict) else {}
                retry = detail.get('retry_after_ms') if isinstance(detail, dict) else None
                self.epoch_retry_at_ms = now_ms + (retry if type(retry) is int else 30_000)
                return
        if op.method == 'operations.get_by_key':
            # Reconcile answered. NOT_FOUND is the daemon's definitive
            # "never admitted"; any other failure leaves the verdict unknown.
            step.detail.pop('reconcile_pending', None)
            self._mark_result(op, 'not_admitted' if code == 'NOT_FOUND' else 'unknown')
            return
        if op.channel == 'bench':
            self._bench_failed(step, op, code, now_ms)
            return
        if op.method == 'messages.submit':
            if code == 'RATE_LIMITED':
                # Same-key re-emit is dedup-stable — the original was never
                # admitted. Requeue the index for a paced retry; the row keeps
                # its identity, only the submission is deferred.
                row = self._result_row(step, op)
                if row is not None:
                    row['result'] = 'retry_pending'
                    retry_ms = self._retry_after_ms(error, 30_000)
                    step.detail.setdefault('retry_queue', []).append(
                        (row['index'], now_ms + retry_ms))
                    return
            elif code in ('NO_REPLY', 'INVALID_REPLY'):
                # Transport loss is not a verdict — the wire may or may not
                # have carried the submit. Evidence comes from get_by_key.
                row = self._result_row(step, op)
                if row is not None:
                    row['result'] = 'unknown'
                if self.epoch:
                    self._emit_reconcile('operations.get_by_key', {
                        'network': self.network, 'admission_epoch': self.epoch,
                        'key': self._op_key(op)}, op, now_ms)
                return
            else:
                # A named admission refusal is evidence, not a step failure —
                # the row records the refusal code and the plan continues.
                self._mark_result(op, f'refused_{code}')
                return
        if op.method in ('members.list', 'nodes.list', 'members.get'):
            # Read-only polls tolerate transient errors; three consecutive
            # failures mean the evidence path itself is broken.
            errors = step.detail.get('poll_errors', 0) + 1
            step.detail['poll_errors'] = errors
            if errors >= 3:
                self._step_done(step, now_ms, 'failed',
                                reason=f'{op.method}: {code}')
            return
        if dangerous:
            self._step_done(step, now_ms, 'incomplete', reason=f'{op.method}: {code}',
                            op=op.tag)
        elif step.spec.get('optional'):
            self._step_done(step, now_ms, 'skipped', reason=f'{op.method}: {code}')
        else:
            self._step_done(step, now_ms, 'failed', reason=f'{op.method}: {code}')

    def _op_done(self, step: StepState, op: Op, result, now_ms: int):
        kind = step.kind
        if op.method == 'operations.open_epoch':
            self.epoch_pending = False
            epoch = (result or {}).get('admission_epoch')
            if isinstance(epoch, str):
                self.epoch = epoch
                self.journal.record({'type': 'epoch', 'epoch': epoch, 'ms': now_ms})
            return
        if op.method == 'operations.get_by_key':
            step.detail.pop('reconcile_pending', None)
            found = isinstance(result, dict) and result.get('operation_id')
            row = None
            for candidate in reversed(self.results):
                if candidate.get('key') and candidate['key'] == self._op_key(op):
                    row = candidate
                    break
            if row is not None:
                row['result'] = 'admitted' if found else 'not_admitted'
                if found:
                    row['operation_id'] = result['operation_id']
                    row['admitted_ms'] = now_ms
                    row['reconciled'] = True
            return
        if op.method == 'messages.submit':
            rec = self._result_row(step, op)
            if rec is not None:
                rec['result'] = 'admitted'
                rec['operation_id'] = (result or {}).get('operation_id')
                rec['superseded'] = (result or {}).get('superseded', [])
            return
        if op.channel == 'bench':
            self._bench_reply(step, op, result if isinstance(result, dict) else {},
                              now_ms)
            return
        if kind == 'rollcall':
            step.detail['rollcall'] = result
            self._step_done(step, now_ms)
        elif kind in ('record_start', 'join_policy', 'report'):
            self._step_done(step, now_ms)
        elif kind == 'gateway_join':
            members = (result or {}).get('members', [])
            gateway = step.detail['gateway']
            # Joined = an active member row: state member and a confirmed
            # membership — first-response timing comes from the member row,
            # never inferred from group counters (D12 honesty).
            if any(isinstance(m, dict)
                   and str(m.get('device_id', '')).lower() == gateway
                   and m.get('state') == 'member'
                   and m.get('confirm_state') == 'active'
                   for m in members):
                self._step_done(step, now_ms, gateway=gateway)
        elif kind == 'sequential_power_on':
            # The power_on reply → settle gap, next board on the next poll.
            step.detail.setdefault('powered', []).append(
                (result or {}).get('node'))
        elif kind == 'formation_wait':
            # Page through nodes.list: a wait for >128 nodes cannot complete
            # on a single page. Pages are disjoint (ascending `after` cursor),
            # so accumulating the row count is exact.
            nodes = (result or {}).get('nodes', [])
            after = (result or {}).get('next_after')
            step.detail['seen'] = step.detail.get('seen', 0) + len(nodes)
            if after and step.detail['seen'] < step.detail['count']:
                self._emit('api1', 'nodes.list',
                           {'limit': 128, 'after': after}, step, now_ms)
                return
            if step.detail['seen'] >= step.detail['count']:
                self._step_done(step, now_ms, seen=step.detail['seen'])
        elif kind == 'reset_rejoin':
            if op.method == 'members.get':
                member = (result or {}).get('member') or {}
                baseline = step.detail.get('baseline')
                if baseline is None:
                    # Pre-reset snapshot — now issue the reset itself.
                    step.detail['baseline'] = {
                        'confirmed_ms': member.get('confirmed_ms'),
                        'last_seen_ms': member.get('last_seen_ms')}
                    self._emit('device', 'reset',
                               {'node': step.detail['target']}, step, now_ms)
                elif step.detail.get('reset_done'):
                    cur = (member.get('confirmed_ms'), member.get('last_seen_ms'))
                    old = (baseline['confirmed_ms'], baseline['last_seen_ms'])
                    fresh = any(type(c) is int and (type(o) is not int or c > o)
                                for c, o in zip(cur, old))
                    if member.get('state') == 'member' and fresh:
                        step.detail['rejoined'] = True
            elif op.method == 'reset':
                step.detail['reset_done'] = now_ms
        elif kind in ('exclusion', 'gk_rotate', 'cutover'):
            self._step_done(step, now_ms, outcome=result)
        elif kind == 'flash_provision':
            self._next_provision(step, now_ms)

    @staticmethod
    def _retry_after_ms(error, default_ms: int) -> int:
        detail = error.get('detail') if isinstance(error, dict) else {}
        value = detail.get('retry_after_ms') if isinstance(detail, dict) else None
        return value if type(value) is int and value > 0 else default_ms

    def _result_row(self, step: StepState, op: Op):
        for row in reversed(self.results):
            if row['step'] == step.index and row.get('key') == self._op_key(op):
                return row
        return None

    def _mark_result(self, op: Op, verdict: str):
        for row in reversed(self.results):
            if row.get('key') and row['key'] == self._op_key(op):
                row['result'] = verdict
                return

    # -- reporting --------------------------------------------------------------

    def summary(self) -> dict:
        steps = [{'index': s.index, 'id': s.id, 'kind': s.kind, 'status': s.status,
                  'started_ms': s.started_ms, 'ended_ms': s.ended_ms,
                  'duration_ms': (s.ended_ms - s.started_ms)
                  if s.started_ms is not None and s.ended_ms is not None else None,
                  'detail': s.detail} for s in self.steps]
        sends = [o for o in self.ops if o.method == 'messages.submit']
        admitted = [o for o in sends if o.ok is True]
        verdicts = {}
        for row in self.results:
            verdicts[row['result']] = verdicts.get(row['result'], 0) + 1
        unknown = sum(1 for o in sends if o.ok is not True)
        # Device-generator evidence (D10/D12): bench commands are the host's
        # only submissions; per-run counters come from the device itself.
        bench_runs = []
        for s in self.steps:
            for r in (s.detail.get('bench') or {}).get('runs', []):
                bench_runs.append({'step': s.index, **r})
        gen_totals = {'planned': 0, 'submitted': 0, 'admitted': 0,
                      'delivered': 0, 'failed': 0, 'unknown': 0}
        dst_totals = {'unique_packets': 0, 'duplicates': 0,
                      'crc_invalid': 0, 'stale_boot': 0, 'unobserved_runs': 0}
        for r in bench_runs:
            status = r.get('status') or {}
            for name in gen_totals:
                gen_totals[name] += status.get(name, 0)
            dst = r.get('dst_count')
            if dst is None:
                dst_totals['unobserved_runs'] += 1
            else:
                dst_totals['unique_packets'] += dst.get('unique_packets', 0)
                dst_totals['duplicates'] += dst.get('duplicates', 0)
                dst_totals['crc_invalid'] += dst.get('crc_invalid', 0)
                if dst.get('state') == rlb1.COUNT_STALE_BOOT:
                    dst_totals['stale_boot'] += 1
        bench_commands = [o for o in self.ops if o.channel == 'bench']
        return {
            'run_id': self.journal.run_id, 'state': self.state,
            'stop_reason': self.stop_reason,
            'steps': steps,
            'sends': {'planned': len(self.results), 'submitted': len(sends),
                      'admitted': len(admitted), 'unknown': unknown,
                      'verdicts': verdicts,
                      # The denominator is always reported; unknowns are
                      # never folded into the success count (D12 honesty).
                      'admit_rate': len(admitted) / len(sends) if sends else None},
            'bench': {
                # Host-side admission cost: the bounded RLB1 commands —
                # the data packets are the device's, counted by the device.
                'host_commands': len(bench_commands),
                'runs': bench_runs,
                'generator': gen_totals,          # source-side counters
                'destination': dst_totals,        # receiver-side counters
            },
            'gaps': self.gaps,
            'incomplete_steps': [s.id for s in self.steps if s.status == 'incomplete'],
        }

    def write_report(self, out_dir) -> dict:
        """Emit the per-run report set: report.json + steps.csv + sends.csv
        + report.md. The CSVs are the external-aggregation surface — their
        rows are exactly the runner's ledger, so an independent reader lands
        on the same verdict counts (design §7.4)."""
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        summary = self.summary()
        (out / 'report.json').write_text(
            json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        rows = ['step_id,kind,status,started_ms,ended_ms,duration_ms']
        for s in summary['steps']:
            rows.append(f"{s['id']},{s['kind']},{s['status']},{s['started_ms'] or ''},"
                        f"{s['ended_ms'] or ''},{s['duration_ms'] or ''}")
        (out / 'steps.csv').write_text('\n'.join(rows) + '\n', encoding='utf-8')
        rows = ['step,index,target,key,planned_ms,submit_ms,late_ms,result,operation_id']
        for r in self.results:
            rows.append(','.join(str(r.get(k) if r.get(k) is not None else '')
                                 for k in ('step', 'index', 'target', 'key',
                                           'planned_ms', 'submit_ms', 'late_ms',
                                           'result', 'operation_id')))
        (out / 'sends.csv').write_text('\n'.join(rows) + '\n', encoding='utf-8')
        # bench_runs.csv — device-generator evidence, one row per bounded
        # run: the source's own counters plus the destination's receive
        # count, kept as separate facts (D10/D12).
        rows = ['step,pair,interval,run,src_boot,dst_boot,outcome,reason,'
                'planned,submitted,admitted,delivered,failed,unknown,'
                'dst_unique,dst_duplicates,dst_crc_invalid,dst_state']
        for r in summary['bench']['runs']:
            status = r.get('status') or {}
            dst = r.get('dst_count') or {}
            rows.append(','.join(str(v if v is not None else '') for v in (
                r.get('step'), r.get('pair'), r.get('interval'), r.get('run'),
                r.get('src_boot'), r.get('dst_boot'), r.get('outcome'),
                r.get('reason'),
                status.get('planned'), status.get('submitted'),
                status.get('admitted'), status.get('delivered'),
                status.get('failed'), status.get('unknown'),
                dst.get('unique_packets'), dst.get('duplicates'),
                dst.get('crc_invalid'), dst.get('state'))))
        (out / 'bench_runs.csv').write_text('\n'.join(rows) + '\n', encoding='utf-8')
        from collections import Counter
        status_counts = Counter(s['status'] for s in summary['steps'])
        lines = [
            f"# scenario run {summary['run_id']}", '',
            f"- state: **{summary['state']}**",
            f"- steps: {len(summary['steps'])} "
            f"({', '.join(f'{k}:{v}' for k, v in sorted(status_counts.items()))})",
            f"- sends: {summary['sends']}",
            f"- gaps: {len(summary['gaps'])}",
        ]
        for s in summary['steps']:
            lines.append(f"  - `{s['id']}` {s['kind']}: {s['status']}"
                         + (f" — {s['detail'].get('reason', '')}" if s['status'] != 'done' else ''))
        (out / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return summary
