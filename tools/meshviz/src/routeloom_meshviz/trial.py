"""Qt-free low-rate unicast send trial: plan validation, pacing ledger and summary.

The runner never owns I/O. The caller asks `due(now_ms)` for requests, sends them over
API1 and feeds replies back, so the same logic runs against the fake server, a live
daemon or a unit test clock.
"""
from dataclasses import asdict, dataclass
import hashlib
import math
import uuid

# Host admission: 2 calls/minute, burst 16, open_epoch and submit both consume it.
ADMISSION_PER_MIN = 2
ADMISSION_BURST = 16
SUSTAINED_INTERVAL_MS = 60_000 // ADMISSION_PER_MIN
MAX_COUNT = 64
# design-devflow.md §5.2: host-issued commands must fit the 96 B HostOps
# payload lane, not the 128 B bare-unicast bound the API accepts.
MAX_PAYLOAD_LEN = 96
POLL_MS = 2000
REPLY_TIMEOUT_MS = 10_000
SETTLE_GRACE_MS = 30_000
TERMINAL = frozenset({'END_SDK_RECEIVED', 'EXPIRED_BEFORE_DISPATCH', 'CANCELLED_BEFORE_DISPATCH',
                      'REJECTED_NOT_ACCEPTED', 'TIME_UNCERTAIN', 'INDETERMINATE'})


@dataclass(frozen=True)
class TrialPlan:
    network: str
    destination: str
    count: int
    interval_ms: int
    payload_len: int
    delivery: str = 'RELIABLE'
    ttl_ms: int = 5000
    seed: int = 1


def _is_hex(value, length):
    return (isinstance(value, str) and len(value) == length and
            all(char in '0123456789abcdef' for char in value.lower()))


def validate(plan: TrialPlan) -> list[str]:
    """Reasons the plan cannot start; empty means admissible within the host budget."""
    errors = []
    if not _is_hex(plan.network, 16) or not 1 <= int(plan.network, 16) <= 0xffffffff:
        errors.append('network は wire-v1 範囲 1..ffffffff の 16 桁 hex')
    if not _is_hex(plan.destination, 16) or int(plan.destination, 16) in (0, 2**64 - 1):
        errors.append('宛先は予約値以外の 16 桁 hex NodeId')
    if type(plan.count) is not int or not 1 <= plan.count <= MAX_COUNT:
        errors.append(f'回数は 1..{MAX_COUNT}')
    if type(plan.interval_ms) is not int or plan.interval_ms < 1000:
        errors.append('間隔は 1 秒以上')
    if type(plan.payload_len) is not int or not 0 <= plan.payload_len <= MAX_PAYLOAD_LEN:
        errors.append(f'payload 長は 0..{MAX_PAYLOAD_LEN} B')
    if plan.delivery not in ('RELIABLE', 'BEST_EFFORT'):
        errors.append('delivery は RELIABLE か BEST_EFFORT')
    if type(plan.ttl_ms) is not int or not 1 <= plan.ttl_ms <= 30_000:
        errors.append('TTL は 1..30000 ms')
    if not errors and plan.count + 1 > ADMISSION_BURST and plan.interval_ms < SUSTAINED_INTERVAL_MS:
        # Beyond the burst only the sustained rate is admissible; faster runs would
        # just collect RATE_LIMITED refusals.
        errors.append(f'admission 上限（毎分 {ADMISSION_PER_MIN} 件・burst {ADMISSION_BURST}）: '
                      f'{ADMISSION_BURST - 1} 回を超える試験は間隔 {SUSTAINED_INTERVAL_MS // 1000} 秒以上')
    return errors


def estimate(plan: TrialPlan) -> dict:
    calls = plan.count + 1
    return {'admission_calls': calls, 'within_burst': calls <= ADMISSION_BURST,
            'duration_ms': (plan.count - 1) * plan.interval_ms + plan.ttl_ms + SETTLE_GRACE_MS}


def nearest_rank(values, q):
    """Nearest-rank quantile: the ceil(q×N)-th ascending sample (1-based)."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(1, math.ceil(q * len(ordered))) - 1]


def _retry_after(error):
    detail = error.get('detail')
    value = detail.get('retry_after_ms') if isinstance(detail, dict) else None
    return value if type(value) is int and value > 0 else SUSTAINED_INTERVAL_MS


class TrialRunner:
    """Draft→Running→Draining→Completed/Aborted with one ledger entry per planned index."""

    def __init__(self, plan: TrialPlan, now_ms: int, run_id: str | None = None,
                 *, reconcile: bool = False):
        errors = validate(plan)
        if errors:
            raise ValueError('; '.join(errors))
        self.plan = plan
        self.reconcile = reconcile
        self.run_id = run_id or uuid.uuid4().hex
        self.state = 'Running'
        self.stop_reason = None
        self.t0 = now_ms
        self.shift_ms = 0
        self.epoch = None
        self.epoch_pending = False
        self.epoch_retry_at_ms = now_ms
        self.next_index = 0
        self.outstanding = {}
        self.tag_counter = 0
        self.last_poll = {}
        self.messages = []
        for index in range(plan.count):
            digest = hashlib.sha256(f'{self.run_id}:{index}'.encode()).hexdigest()
            self.messages.append({'run_id': self.run_id, 'index': index, 'key': digest[:32],
                                  'destination': plan.destination, 'payload_len': plan.payload_len,
                                  'planned_ms': None, 'submit_ms': None, 'admitted_ms': None,
                                  'terminal_ms': None, 'operation_id': None, 'admission': None,
                                  'dispatch_state': None, 'result': 'planned'})

    def payload_hex(self, index):
        seed = f'{self.plan.seed}:{self.run_id}:{index}'.encode()
        body = b''
        while len(body) < self.plan.payload_len:
            body += hashlib.sha256(seed + len(body).to_bytes(4, 'big')).digest()
        return body[:self.plan.payload_len].hex()

    def _tag(self, kind, index, now_ms):
        self.tag_counter += 1
        tag = f'{self.run_id[:8]}-{self.tag_counter}'
        self.outstanding[tag] = (kind, index, now_ms)
        return tag

    def due(self, now_ms):
        """Requests to send now as (tag, method, params); at most one admission call in flight."""
        requests = []
        for tag, (_, _, sent) in list(self.outstanding.items()):
            if now_ms - sent > REPLY_TIMEOUT_MS:
                self.on_reply(tag, None, now_ms)
        if self.state not in ('Running', 'Draining'):
            return requests
        admission_busy = any(kind in ('epoch', 'submit') for kind, _, _ in self.outstanding.values())
        if self.state == 'Running' and not admission_busy:
            if self.epoch is None:
                if not self.epoch_pending and now_ms >= self.epoch_retry_at_ms:
                    self.epoch_pending = True
                    tag = self._tag('epoch', None, now_ms)
                    requests.append((tag, 'operations.open_epoch', {'network': self.plan.network}))
            elif self.next_index < self.plan.count:
                index = self.next_index
                planned = self.t0 + self.shift_ms + index * self.plan.interval_ms
                if now_ms >= planned:
                    message = self.messages[index]
                    message['planned_ms'] = planned
                    message['submit_ms'] = now_ms
                    self.next_index += 1
                    tag = self._tag('submit', index, now_ms)
                    requests.append((tag, 'messages.submit', {
                        'network': self.plan.network, 'admission_epoch': self.epoch,
                        'key': message['key'],
                        'destination': {'kind': 'node', 'id': self.plan.destination},
                        'payload_hex': self.payload_hex(index), 'payload_len': self.plan.payload_len,
                        'options': {'delivery': self.plan.delivery, 'ttl_ms': self.plan.ttl_ms,
                                    'storage': 'RAM_ONLY'}}))
            if self.next_index >= self.plan.count and self.epoch is not None:
                self.state = 'Draining'
        polling = {index for kind, index, _ in self.outstanding.values()
                   if kind in ('poll', 'lookup')}
        for message in self.messages:
            if message['submit_ms'] is None or message['terminal_ms'] is not None:
                continue
            index = message['index']
            if now_ms - message['submit_ms'] > self.plan.ttl_ms + SETTLE_GRACE_MS:
                # Not settled by the deadline: the result stays unknown, never failed.
                message['result'] = 'unknown'
                message['terminal_ms'] = now_ms
                continue
            if message['operation_id'] is None:
                if (self.reconcile and message['admission'] in ('NO_REPLY', 'INVALID_REPLY') and
                        index not in polling
                        and now_ms - self.last_poll.get(index, -POLL_MS) >= POLL_MS):
                    self.last_poll[index] = now_ms
                    tag = self._tag('lookup', index, now_ms)
                    requests.append((tag, 'operations.get_by_key', {
                        'network': self.plan.network, 'admission_epoch': self.epoch,
                        'key': message['key']}))
                continue
            if index not in polling and now_ms - self.last_poll.get(index, -POLL_MS) >= POLL_MS:
                self.last_poll[index] = now_ms
                tag = self._tag('poll', index, now_ms)
                requests.append((tag, 'operations.get', {'operation_id': message['operation_id']}))
        self._maybe_finish()
        return requests

    def on_reply(self, tag, reply, now_ms):
        """reply is the decoded API1 response, or None when the transport lost it."""
        entry = self.outstanding.pop(tag, None)
        if entry is None:
            return
        kind, index, _ = entry
        ok = isinstance(reply, dict) and reply.get('ok') is True
        result = reply.get('result') if ok else None
        if ok and (not isinstance(result, dict) or kind == 'submit' and
                   not isinstance(result.get('operation_id'), str)):
            ok = False
        error = reply.get('error', {}) if isinstance(reply, dict) and not ok else {}
        if not isinstance(error, dict):
            error = {}
        code = ('NO_REPLY' if reply is None else error.get('code') or 'INVALID_REPLY')
        if kind == 'epoch':
            self.epoch_pending = False
            if ok and _is_hex(result.get('admission_epoch'), 16):
                self.epoch = result['admission_epoch']
                self.t0 = now_ms
            elif code == 'RATE_LIMITED':
                self.epoch_retry_at_ms = now_ms + _retry_after(error)
            else:
                self.abort(f'open_epoch: {code}')
        elif kind == 'submit':
            message = self.messages[index]
            if ok:
                message.update(admission='ACCEPTED', admitted_ms=now_ms,
                               operation_id=result.get('operation_id'),
                               dispatch_state=result.get('dispatch_state'), result='admitted')
                self._settle(message, now_ms)
            else:
                # Admission refusals are not delivery failures. A lost reply stays unknown
                # until key lookup resolves it; the same index is never resubmitted.
                unknown = code in ('NO_REPLY', 'INVALID_REPLY')
                message.update(admission=code, result='unknown' if unknown else 'refused',
                               terminal_ms=None if unknown and self.reconcile else now_ms)
                if code == 'RATE_LIMITED':
                    self.shift_ms += _retry_after(error)
        elif kind == 'lookup' and ok:
            message = self.messages[index]
            if isinstance(result.get('operation_id'), str):
                message.update(admission='ACCEPTED', operation_id=result['operation_id'],
                               dispatch_state=result.get('dispatch_state'), result='admitted')
                self._settle(message, now_ms)
        elif kind == 'poll' and ok:
            message = self.messages[index]
            message['dispatch_state'] = result.get('dispatch_state')
            self._settle(message, now_ms)
        self._maybe_finish()

    @staticmethod
    def _settle(message, now_ms):
        if message['dispatch_state'] in TERMINAL and message['terminal_ms'] is None:
            message['terminal_ms'] = now_ms
            message['result'] = message['dispatch_state']

    def abort(self, reason='利用者が停止', *, drain=True):
        """Stop new submissions. Without drain (source closed) unsettled results become unknown."""
        if self.state in ('Completed', 'Aborted'):
            return
        if not drain:
            self.outstanding.clear()
            for message in self.messages:
                if message['submit_ms'] is not None and message['terminal_ms'] is None:
                    message['result'] = 'unknown'
        # Stop new submissions; already admitted messages keep draining.
        self.stop_reason = reason
        for message in self.messages[self.next_index:]:
            message['result'] = 'not_sent'
        self.next_index = self.plan.count
        self.state = 'Draining' if drain and (self.outstanding or any(
            m['operation_id'] and m['terminal_ms'] is None for m in self.messages)) else 'Aborted'

    def _maybe_finish(self):
        if (self.state == 'Draining' and not self.outstanding and
                all(m['terminal_ms'] is not None or m['result'] in ('planned', 'not_sent')
                    for m in self.messages)):
            self.state = 'Aborted' if self.stop_reason else 'Completed'

    @property
    def finished(self):
        return self.state in ('Completed', 'Aborted')

    def summary(self):
        return summarize(self.messages, self.plan, self.state, self.stop_reason)


def summarize(messages, plan=None, state=None, stop_reason=None):
    """Counters and nearest-rank latency; unknown results never count as success."""
    submitted = [m for m in messages if m['submit_ms'] is not None]
    admitted = [m for m in submitted if m['admission'] == 'ACCEPTED']
    success = [m for m in admitted if m['result'] == 'END_SDK_RECEIVED']
    unknown = [m for m in messages if m['result'] in ('unknown', 'admitted')]
    outcomes = {}
    for message in messages:
        outcomes[message['result']] = outcomes.get(message['result'], 0) + 1
    refused = {}
    for message in submitted:
        if message['admission'] not in (None, 'ACCEPTED', 'NO_REPLY', 'INVALID_REPLY'):
            refused[message['admission']] = refused.get(message['admission'], 0) + 1
    latency = [m['terminal_ms'] - m['submit_ms'] for m in success]
    admit_latency = [m['admitted_ms'] - m['submit_ms'] for m in admitted
                     if type(m['admitted_ms']) is int]
    unknown_admitted = len([m for m in admitted if m['result'] in ('unknown', 'admitted')])
    return {
        'plan': asdict(plan) if plan else None, 'state': state, 'stop_reason': stop_reason,
        'planned': len(messages), 'submitted': len(submitted), 'admitted': len(admitted),
        'refused': refused, 'success': len(success), 'unknown': len(unknown),
        'outcomes': outcomes,
        # Unknown results bound the rate: success/admitted .. (success+unknown)/admitted.
        'success_rate_min': len(success) / len(admitted) if admitted else None,
        'success_rate_max': (len(success) + unknown_admitted) / len(admitted) if admitted else None,
        'latency_ms': {name: nearest_rank(latency, q) for name, q in
                       (('p50', .5), ('p90', .9), ('p95', .95), ('p99', .99))} |
                      {'min': min(latency, default=None), 'max': max(latency, default=None),
                       'n': len(latency)},
        'admission_latency_ms_p50': nearest_rank(admit_latency, .5),
    }
