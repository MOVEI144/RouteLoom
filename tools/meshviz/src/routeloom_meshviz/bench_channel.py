"""Bench device channel (design-devflow §5.2/§5.4): drives RLB1 commands
to `bench_node` devices over the API1 surface — no separate transport.

A bench command is a bounded two-step exchange on the daemon socket:

1. `messages.submit` — the RLB1 frame rides as an end-protected unicast
   application payload to the bench node (admission-charged once, like
   any host write). The idempotency key is derived from
   `(run_uuid, command_seq)`, so a journaled re-issue dedups at the host
   AND inside the device's command log — a redelivered START returns
   DUPLICATE, never a second generator run.
2. `messages.read` — the device's unicast reply surfaces in the receive
   log; it is matched by `(origin, run_uuid, seq, reply opcode,
   FLAG_RESPONSE)` — nothing else counts as the answer.

The channel is synchronous from the runner's view: `execute` returns one
honest verdict per command — the decoded reply body, a named refusal, or
`BENCH_NO_REPLY` when the device stayed silent inside the window. Replies
for other in-flight calls seen while polling are forwarded through `feed`
so no foreign evidence is ever consumed.
"""

import hashlib
import time

from . import rlb1

# One bench command's round trip: submit admit + device reply + slack.
REPLY_TIMEOUT_MS = 4_000
# messages.read long-poll slice inside the reply window.
READ_WAIT_MS = 400

# Command encoders: bench op name -> (request opcode, expected reply opcode).
_OPS = {
    'hello': (rlb1.Opcode.HELLO, rlb1.Opcode.CAPABILITIES),
    'peer_send_start': (rlb1.Opcode.PEER_SEND_START, rlb1.Opcode.PEER_SEND_STATUS),
    'peer_send_status': (rlb1.Opcode.PEER_SEND_STATUS, rlb1.Opcode.PEER_SEND_STATUS),
    'peer_send_stop': (rlb1.Opcode.PEER_SEND_STOP, rlb1.Opcode.PEER_SEND_STATUS),
    'count_get': (rlb1.Opcode.COUNT_GET, rlb1.Opcode.COUNT_STATUS),
}

_DECODE = {
    'hello': rlb1.decode_capabilities,
    'peer_send_start': rlb1.decode_peer_send_status,
    'peer_send_status': rlb1.decode_peer_send_status,
    'peer_send_stop': rlb1.decode_peer_send_status,
    'count_get': rlb1.decode_count_status,
}


def _body(method: str, params: dict) -> bytes:
    if method == 'peer_send_start':
        return rlb1.encode_peer_send_start(
            expected_boot=params['expected_boot'],
            expected_dest_boot=params['expected_dest_boot'],
            destination=int(params['destination'], 16),
            sequence_begin=params['sequence_begin'],
            count=params['count'], payload_len=params['payload_len'],
            seed=params['seed'], interval_ms=params['interval_ms'],
            ttl_ms=params['ttl_ms'], max_inflight=params['max_inflight'])
    if method == 'peer_send_stop':
        return rlb1.encode_expected_boot(params['expected_boot'])
    return b''                       # hello / peer_send_status / count_get


def _err(code, **detail):
    return {'ok': False, 'error': {'code': code,
                                   'detail': {'message': code, **detail}}}


class BenchChannel:
    """One synchronous RLB1 exchange per call over a shared API1 socket.

    `feed(tag, reply)` is invoked for every daemon reply that is not part
    of the current exchange — the caller routes it back to the runner so
    polling a device never eats another operation's answer.
    """

    def __init__(self, api1, network: str, *, reply_timeout_ms=REPLY_TIMEOUT_MS):
        self.api1 = api1                 # scenario_driver.Api1Socket
        self.network = network
        self.reply_timeout_ms = reply_timeout_ms
        self.epoch = None
        self.cursor = None               # anchored 'latest' on first read
        self._tag_seq = 0

    def execute(self, call, feed) -> dict:
        method = call.method
        if method not in _OPS:
            return _err('UNKNOWN_BENCH_OP', method=method)
        params = call.params
        try:
            opcode, expect = _OPS[method]
            run = bytes.fromhex(params['run'])
            body = _body(method, params)
            frame = rlb1.encode(opcode, 0, run, params['seq'], body)
        except (KeyError, ValueError, TypeError) as exc:
            return _err('INVALID_ARGUMENT', detail=str(exc)[:200])
        node = params['node']
        deadline = time.monotonic() + self.reply_timeout_ms / 1000
        epoch = self._ensure_epoch(feed, deadline)
        if epoch is not True:
            return epoch               # an error reply dict
        anchor = self._anchor(feed, deadline)
        if anchor is not None:
            return anchor
        submit = self._submit(node, frame, params, feed, deadline)
        if submit is not None:
            return submit              # a named refusal/error
        return self._collect(node, run, params['seq'], expect, method,
                             feed, deadline)

    # -- internals -------------------------------------------------------

    def _roundtrip(self, tag, method, params, feed, deadline):
        """Send one API1 request; wait for its reply. Foreign replies are
        fed back to the runner — polling for a bench reply must not starve
        or swallow another op's answer."""
        try:
            self.api1.send(_Call(tag, method, params))
        except OSError:
            return _err('TRANSPORT')
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            try:
                replies = self.api1.poll(min(200, max(1, int(left * 1000))))
            except (ConnectionError, OSError):
                return _err('TRANSPORT')
            mine = None
            for rid, reply in replies:
                if rid == tag:
                    mine = reply
                else:
                    feed(rid, reply)
            if mine is not None:
                return mine

    def _ensure_epoch(self, feed, deadline):
        if self.epoch is not None:
            return True
        self._tag_seq += 1
        reply = self._roundtrip(f'bench-epoch-{self._tag_seq}',
                                'operations.open_epoch',
                                {'network': self.network}, feed, deadline)
        if reply is None:
            return _err('NO_REPLY')
        if not reply.get('ok'):
            return reply
        epoch = (reply.get('result') or {}).get('admission_epoch')
        if not isinstance(epoch, str):
            return _err('INVALID_REPLY')
        self.epoch = epoch
        return True

    def _anchor(self, feed, deadline):
        """Pin the read cursor BEFORE the submit — a reply that lands between
        submit and the first read would sit behind a 'latest' anchor taken
        afterwards and be missed forever."""
        if self.cursor is not None:
            return None
        self._tag_seq += 1
        reply = self._roundtrip(f'bench-anchor-{self._tag_seq}',
                                'messages.read',
                                {'network': self.network, 'from': 'latest',
                                 'limit': 1}, feed, deadline)
        if reply is None:
            return _err('NO_REPLY')
        if not reply.get('ok'):
            return reply
        self.cursor = (reply.get('result') or {}).get('next_cursor')
        return None

    def _submit(self, node, frame: bytes, params, feed, deadline):
        """Admission-charged submit carrying the RLB1 frame. The key is
        unique per runner op (`op_tag`): daemon dedup would hide a re-issue
        from a device that never got the first attempt — dedup is the
        device's job, keyed by (run, seq) inside the frame."""
        key = hashlib.sha256(
            f"bench:{params.get('op_tag', '')}:{node}:{params['run']}:"
            f"{params['seq']}".encode()).hexdigest()[:32]
        while True:
            self._tag_seq += 1
            reply = self._roundtrip(
                f'bench-sub-{self._tag_seq}', 'messages.submit', {
                    'network': self.network, 'admission_epoch': self.epoch,
                    'key': key,
                    'destination': {'kind': 'node', 'id': node},
                    'payload_hex': frame.hex(), 'payload_len': len(frame),
                    'options': {'delivery': 'RELIABLE', 'storage': 'RAM_ONLY',
                                'ttl_ms': min(params.get('ttl_ms', 5000), 30_000)}},
                feed, deadline)
            if reply is None:
                return _err('NO_REPLY')
            if reply.get('ok'):
                return None
            error = reply.get('error') or {}
            if error.get('code') != 'RATE_LIMITED':
                return reply
            # Admission is a paced retry under the SAME key — dedup keeps it
            # one logical command (same rule as the runner's send steps).
            detail = error.get('detail') or {}
            retry_ms = detail.get('retry_after_ms', 1000)
            if not isinstance(retry_ms, int) or retry_ms <= 0:
                retry_ms = 1000
            if time.monotonic() + retry_ms / 1000 >= deadline:
                return reply           # the refusal stands — honestly reported
            time.sleep(retry_ms / 1000)

    def _collect(self, node, run: bytes, seq: int, expect: int, method: str,
                 feed, deadline) -> dict:
        node = node.lower()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return _err('BENCH_NO_REPLY', node=node)
            params = {'network': self.network, 'limit': 128,
                      'wait_ms': min(READ_WAIT_MS, int(left * 1000))}
            if self.cursor is not None:
                params['cursor'] = self.cursor
            else:
                params['from'] = 'latest'
            self._tag_seq += 1
            reply = self._roundtrip(f'bench-read-{self._tag_seq}',
                                    'messages.read', params, feed, deadline)
            if reply is None:
                return _err('NO_REPLY')
            if not reply.get('ok'):
                return reply
            result = reply.get('result') or {}
            self.cursor = result.get('next_cursor') or self.cursor
            for record in result.get('records') or []:
                if not isinstance(record, dict) or record.get('origin') != node:
                    continue
                try:
                    msg = rlb1.decode(bytes.fromhex(record.get('payload_hex', '')))
                except ValueError:
                    continue
                if (msg['run'] == run and msg['sequence'] == seq and
                        msg['opcode'] == expect and
                        msg['flags'] & rlb1.FLAG_RESPONSE):
                    try:
                        return {'ok': True,
                                'result': {**_DECODE[method](msg['body']),
                                           'flags': msg['flags']}}
                    except ValueError:
                        return _err('BENCH_DECODE', node=node)
            if not result.get('records'):
                # Fake/short daemons may not honor wait_ms — pace the next
                # read so the poll loop never spins hot.
                time.sleep(min(0.05, left))


class _Call:
    """Minimal api1.send() payload (tag/method/params shape)."""

    def __init__(self, tag, method, params):
        self.tag = tag
        self.method = method
        self.params = params
