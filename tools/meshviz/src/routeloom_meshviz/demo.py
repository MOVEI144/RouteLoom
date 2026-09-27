"""Deterministic synthetic mesh for the fake API1 server and demo captures (no Qt/USB).

The gateway view mirrors API1 `nodes.list`: multi-hop hop counts stay null and RSSI is
only reported for direct neighbors. Demo captures additionally carry per-node
parent routes, which today's API1 does not expose, so the GUI can be exercised on
gateway-tree data before the topology API exists.
"""
import hashlib
import math
import threading
import time

from .capture import Capture
from .model import FakeClock
from . import rlb1

GATEWAY = f'{1:016x}'
TERMINAL_STATES = frozenset({'END_SDK_RECEIVED', 'EXPIRED_BEFORE_DISPATCH',
                             'CANCELLED_BEFORE_DISPATCH', 'REJECTED_NOT_ACCEPTED',
                             'TIME_UNCERTAIN', 'INDETERMINATE'})


class FakeMethodError(Exception):
    def __init__(self, code, retryable=False, **detail):
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.detail = detail


class DemoMesh:
    """Fan-out-3 tree whose relay 2 fails and whose last node leaves periodically."""
    METHODS = ('operations.open_epoch', 'messages.submit', 'messages.read',
               'operations.get', 'operations.get_by_key')
    RATE_PER_MIN = 2
    BURST = 16

    def __init__(self, count=8, *, period_ms=40_000, clock=None):
        if type(count) is not int or not 2 <= count <= 160:
            raise ValueError('demo mesh supports 2..160 nodes')
        self.ids = [f'{i:016x}' for i in range(1, count + 1)]
        self.period_ms = period_ms
        # clock() returns (mono_ms, unix_ms); tests pass a FakeClock-backed function.
        self.clock = clock or (lambda: (time.monotonic_ns() // 1_000_000, time.time_ns() // 1_000_000))
        self.start_mono, self.start_unix = self.clock()
        self.lock = threading.Lock()
        self.epochs = 0
        self.ops = {}
        self.keys = {}
        self.tokens = float(self.BURST)
        self.tokens_at = self.start_mono
        # Bench simulation: every node id is a bench-capable device. A submit
        # carrying an RLB1 frame is dispatched to the fake device; its reply
        # lands in rx_log, surfaced by messages.read with real cursors.
        self.rx_log = []                  # received device→host records
        self.bench_commands = {}          # (node, run, seq) seen — cmd dedup
        self.bench_runs = {}              # run_uuid -> live generator state
        self.bench_counts = {}            # (node, run_uuid) -> packets seen

    @staticmethod
    def _index(node):
        return int(node, 16)

    def _base_parent(self, node):
        i = self._index(node)
        return None if i == 1 else f'{1 + (i - 2) // 3:016x}'

    def topology(self, elapsed_ms):
        """Return ({node: parent-or-None}, offline set, departed set) at elapsed time."""
        phase = elapsed_ms % self.period_ms
        offline, departed = set(), set()
        if len(self.ids) > 2 and self.period_ms * 3 // 8 <= phase < self.period_ms * 6 // 8:
            offline.add(self.ids[1])
        if len(self.ids) > 3 and phase >= self.period_ms * 6 // 8:
            departed.add(self.ids[-1])
        parents = {}
        for node in self.ids:
            if node in offline or node in departed:
                continue
            parent = self._base_parent(node)
            # An orphan re-attaches to its nearest live ancestor: a route switch.
            while parent is not None and (parent in offline or parent in departed):
                parent = self._base_parent(parent)
            parents[node] = parent
        return parents, offline, departed

    @staticmethod
    def _depth(parents, node):
        depth = 0
        while parents.get(node) is not None and depth < 200:
            node = parents[node]
            depth += 1
        return depth

    def rssi(self, node, depth, elapsed_ms):
        i = self._index(node)
        wobble = round(3 * math.sin(elapsed_ms / 5000 + i))
        return -42 - 6 * min(depth, 5) - (i * 7) % 6 + wobble

    def gateway_nodes(self):
        """API1 nodes.list items as the gateway would report them now."""
        mono, unix = self.clock()
        elapsed = mono - self.start_mono
        parents, offline, departed = self.topology(elapsed)
        items = []
        for node in self.ids:
            base = {'node': node, 'role': 'gateway' if node == GATEWAY else 'peer',
                    'neighbor': False, 'direct': False, 'hops': None, 'next_hop': None,
                    'route_metric': None, 'link_cost': None, 'rssi_dbm': None,
                    'rssi_avg_dbm': None, 'telemetry_stale': None,
                    'updated_ms': unix, 'changed_ms': self.start_unix}
            if node == GATEWAY:
                items.append({**base, 'connected': True, 'listed': True, 'hops': 0,
                              'telemetry_stale': False, 'last_heard_ms': unix, 'heard_age_ms': 0})
                continue
            if node not in parents:
                since = elapsed % self.period_ms - (self.period_ms * 6 // 8 if node in departed
                                                    else self.period_ms * 3 // 8)
                lost = unix - max(since, 0)
                items.append({**base, 'connected': False, 'listed': node not in departed,
                              'last_heard_ms': lost, 'heard_age_ms': unix - lost})
                continue
            depth = self._depth(parents, node)
            first = node
            while parents[first] != GATEWAY:
                first = parents[first]
            direct = parents[node] == GATEWAY
            heard = unix - (self._index(node) * 37) % 900
            rssi = self.rssi(node, depth, elapsed) if direct else None
            items.append({**base, 'connected': True, 'listed': True, 'neighbor': direct,
                          'direct': direct, 'hops': 1 if direct else None, 'next_hop': first,
                          'route_metric': depth * 10, 'link_cost': 10 if direct else None,
                          'rssi_dbm': rssi, 'rssi_avg_dbm': rssi, 'telemetry_stale': False,
                          'last_heard_ms': heard, 'heard_age_ms': unix - heard})
        return items

    def observer_payload(self, now_mono_ns):
        """Per-node parent links and routes (future topology API shape) for demo captures."""
        mono, _ = self.clock()
        elapsed = mono - self.start_mono
        parents, _, _ = self.topology(elapsed)
        links, routes = [], []
        for node, parent in parents.items():
            if parent is None:
                continue
            depth = self._depth(parents, node)
            links.append({'observer': node, 'peer': parent, 'rssi_dbm': self.rssi(node, depth, elapsed),
                          'direction': 'peer_to_observer', 'evidence': 'demo'})
            routes.append({'observer': node, 'destination': GATEWAY, 'next_hop': parent,
                           'valid': True, 'sample_mono_ns': now_mono_ns, 'evidence': 'demo'})
        return links, routes

    # --- fake API1 send subset (bounded, same admission budget as the host) ---

    def handle(self, method, params):
        with self.lock:
            mono, unix = self.clock()
            if method == 'operations.get':
                if set(params) != {'operation_id'} or params['operation_id'] not in self.ops:
                    raise FakeMethodError('NOT_FOUND')
                return self._record(self.ops[params['operation_id']], mono)
            network = params.get('network')
            if not _network(network):
                raise FakeMethodError('INVALID_ARGUMENT')
            if method == 'messages.read':
                if set(params) - {'network', 'from', 'cursor', 'limit', 'wait_ms'}:
                    raise FakeMethodError('INVALID_ARGUMENT')
                limit = params.get('limit', 128)
                if type(limit) is not int or not 1 <= limit <= 128:
                    raise FakeMethodError('INVALID_ARGUMENT')
                cursor = params.get('cursor')
                start = 0
                if cursor is not None:
                    try:
                        start = int(cursor, 16)
                    except (TypeError, ValueError):
                        raise FakeMethodError('INVALID_CURSOR')
                elif params.get('from') == 'latest':
                    start = len(self.rx_log)
                page = self.rx_log[start:start + limit]
                end = start + len(page)
                return {'records': [dict(r, cursor=f'{i + 1:08x}')
                                    for i, r in enumerate(page, start)],
                        'next_cursor': f'{max(end, start):08x}',
                        'oldest_cursor': f'{0:08x}',
                        'tail_cursor': f'{len(self.rx_log):08x}',
                        'more': end < len(self.rx_log),
                        'retention': {'seconds': 0, 'entries': len(self.rx_log),
                                      'bytes': sum(len(r['payload_hex']) // 2
                                                   for r in self.rx_log)}}
            if method == 'operations.get_by_key':
                if (set(params) != {'network', 'admission_epoch', 'key'} or
                        not _hex(params['admission_epoch'], 16) or not _hex(params['key'], 32)):
                    raise FakeMethodError('INVALID_ARGUMENT')
                op_id = self.keys.get((network, params['admission_epoch'], params['key']))
                if op_id is None:
                    raise FakeMethodError('NOT_FOUND')
                return self._record(self.ops[op_id], mono)
            if method == 'operations.open_epoch':
                if set(params) != {'network'}:
                    raise FakeMethodError('INVALID_ARGUMENT')
                self._admit(mono)
                self.epochs += 1
                return {'network': network, 'admission_epoch': f'{self.epochs:016x}'}
            destination = params.get('destination')
            options = params.get('options') or {}
            payload = params.get('payload_hex')
            if (not _hex(params.get('admission_epoch'), 16) or not _hex(params.get('key'), 32) or
                    not isinstance(destination, dict) or destination.get('kind') != 'node' or
                    not _hex(destination.get('id'), 16) or
                    int(destination['id'], 16) in (0, 2**64 - 1) or
                    not isinstance(payload, str) or
                    len(payload) % 2 or params.get('payload_len') != len(payload) // 2 or
                    params['payload_len'] > 128 or
                    options.get('delivery', 'RELIABLE') not in ('RELIABLE', 'BEST_EFFORT')):
                raise FakeMethodError('INVALID_ARGUMENT')
            identity = (network, params['admission_epoch'], params['key'])
            digest = hashlib.sha256(repr(sorted(params.items())).encode()).hexdigest()
            self._admit(mono)
            if identity in self.keys:
                op = self.ops[self.keys[identity]]
                if op['digest'] != digest:
                    raise FakeMethodError('CONFLICT', existing_operation_id=op['operation_id'])
                return self._record(op, mono)
            reachable = any(n['node'] == destination['id'] and n['connected']
                            for n in self.gateway_nodes())
            op_id = f'{"d" * 32}:{len(self.ops) + 1:016x}'
            self.ops[op_id] = {'operation_id': op_id, 'digest': digest, 'submitted': mono,
                               'reachable': reachable,
                               'delivery': options.get('delivery', 'RELIABLE'),
                               'ttl_ms': options.get('ttl_ms', 5000)}
            self.keys[identity] = op_id
            # A payload that decodes as RLB1 is a bench command for the
            # destination device — the fake answers it like a bench_node
            # would (bounded run, dedup'd commands, receiver-side counts).
            try:
                msg = rlb1.decode(bytes.fromhex(payload))
            except ValueError:
                msg = None
            if msg is not None and not msg['flags'] & rlb1.FLAG_RESPONSE:
                self._bench_dispatch(destination['id'], msg, mono)
            return self._record(self.ops[op_id], mono)

    # --- fake bench_node (RLB1 device half) ---------------------------------

    def _bench_dispatch(self, node: str, msg: dict, mono: int):
        """Device-side command handling — mirrors the firmware contract:
        commands dedup by (node, run, seq); replies carry FLAG_RESPONSE."""
        opcode = msg['opcode']
        run = msg['run']
        key = (node, run.hex(), msg['sequence'])
        if key in self.bench_commands:
            # Duplicate command: re-answer with the DUPLICATE flag — never
            # re-dispatched, so a re-issued START can't mint a second run.
            reply = self.bench_commands[key]
            flags = reply[1] | rlb1.FLAG_DUPLICATE
            self._bench_reply(node, reply[0], flags, run, msg['sequence'],
                              reply[2])
            return
        if opcode == rlb1.Opcode.HELLO:
            body = rlb1._capabilities({
                'app_protocol': 1, 'app_version': 1,
                'max_unicast_body': rlb1.MAX_BODY,
                'max_group_body': rlb1.MAX_GROUP_BODY,
                'max_command_body': rlb1.MAX_COMMAND_BODY,
                'run_slots': 1, 'reply_queue': 2, 'generator_max_inflight': 1,
                'boot_incarnation': self._boot(node),
                'firmware_digest': 0xBEC00000 | self._index(node),
                'config_digest': 0,
                'opcodes': list(rlb1.REPLY_OPCODES | {rlb1.Opcode.HELLO,
                                rlb1.Opcode.COUNT_GET, rlb1.Opcode.PEER_SEND_START,
                                rlb1.Opcode.PEER_SEND_STOP,
                                rlb1.Opcode.PEER_SEND_STATUS})})
            self._bench_reply(node, rlb1.Opcode.CAPABILITIES,
                              rlb1.FLAG_RESPONSE, run, msg['sequence'], body,
                              dedup_key=key)
        elif opcode == rlb1.Opcode.PEER_SEND_START:
            try:
                start = rlb1.decode_peer_send_start(msg['body'])
            except ValueError:
                self._bench_reply(node, rlb1.Opcode.PEER_SEND_STATUS,
                                  rlb1.FLAG_RESPONSE, run, msg['sequence'],
                                  _status_body(rlb1.PS_INVALID, rlb1.GEN_IDLE),
                                  dedup_key=key)
                return
            if start['expected_boot'] not in (0, self._boot(node)):
                self._bench_reply(node, rlb1.Opcode.PEER_SEND_STATUS,
                                  rlb1.FLAG_RESPONSE, run, msg['sequence'],
                                  _status_body(rlb1.PS_STALE_BOOT, rlb1.GEN_IDLE),
                                  dedup_key=key)
                return
            busy = any(r['node'] == node and
                       self._gen_state(r, mono) not in rlb1.GEN_TERMINAL
                       for r in self.bench_runs.values())
            if busy:
                self._bench_reply(node, rlb1.Opcode.PEER_SEND_STATUS,
                                  rlb1.FLAG_RESPONSE, run, msg['sequence'],
                                  _status_body(rlb1.PS_BUSY, rlb1.GEN_IDLE),
                                  dedup_key=key)
                return
            self.bench_runs[run.hex()] = {
                'node': node, 'dst': f"{start['destination']:016x}",
                'run_hex': run.hex(),
                'count': start['count'], 'interval_ms': start['interval_ms'],
                't0': mono, 'stop_at': None}
            self._bench_reply(node, rlb1.Opcode.PEER_SEND_STATUS,
                              rlb1.FLAG_RESPONSE, run, msg['sequence'],
                              _status_body(rlb1.PS_STARTED, rlb1.GEN_RUNNING),
                              dedup_key=key)
        elif opcode == rlb1.Opcode.PEER_SEND_STATUS:
            live = self.bench_runs.get(run.hex())
            if live is None or live['node'] != node:
                self._bench_reply(node, rlb1.Opcode.PEER_SEND_STATUS,
                                  rlb1.FLAG_RESPONSE, run, msg['sequence'],
                                  _status_body(rlb1.PS_NOT_RUNNING,
                                               rlb1.GEN_IDLE), dedup_key=key)
                return
            state = self._gen_state(live, mono)
            self._bench_reply(node, rlb1.Opcode.PEER_SEND_STATUS,
                              rlb1.FLAG_RESPONSE, run, msg['sequence'],
                              _status_body(rlb1.PS_QUERY, state,
                                           counters=self._gen_counters(live, mono)),
                              dedup_key=key)
        elif opcode == rlb1.Opcode.PEER_SEND_STOP:
            live = self.bench_runs.get(run.hex())
            if live is None or live['node'] != node:
                body = _status_body(rlb1.PS_NOT_RUNNING, rlb1.GEN_IDLE)
            else:
                live['stop_at'] = mono
                body = _status_body(rlb1.PS_STOPPED, rlb1.GEN_STOPPED,
                                    counters=self._gen_counters(live, mono))
            self._bench_reply(node, rlb1.Opcode.PEER_SEND_STATUS,
                              rlb1.FLAG_RESPONSE, run, msg['sequence'], body,
                              dedup_key=key)
        elif opcode == rlb1.Opcode.COUNT_GET:
            seen = self.bench_counts.get((node, run.hex()), 0)
            state = rlb1.COUNT_ACTIVE if seen else rlb1.COUNT_UNKNOWN
            body = rlb1.encode_count_status({
                'state': state, 'unique_packets': seen,
                'unique_bytes': seen * 16, 'duplicates': 0, 'crc_invalid': 0,
                'first_ms': 0, 'last_ms': 0, 'window_base': seen,
                'window': (1 << seen) - 1})
            self._bench_reply(node, rlb1.Opcode.COUNT_STATUS,
                              rlb1.FLAG_RESPONSE, run, msg['sequence'], body,
                              dedup_key=key)
        # Unknown opcodes are well-formed headers the app ignores — no reply.

    def _bench_reply(self, node, opcode, flags, run, seq, body, dedup_key=None):
        if dedup_key is not None:
            self.bench_commands[dedup_key] = (opcode, flags, body)
        self.rx_log.append({'v': 1, 'network': f'{1:016x}',
                            'gateway': None, 'origin': node,
                            'message': {'session': '00000001',
                                        'sequence': f'{seq:016x}'},
                            'payload_hex': rlb1.encode(opcode, flags, run,
                                                       seq, body).hex(),
                            'payload_len': rlb1.HEADER_SIZE + len(body),
                            'endpoint_kind': 'node_data',
                            'evidence': 'HOST_RAM_RETAINED'})

    def _boot(self, node):
        return 1 + self._index(node)

    def _gen_state(self, run, mono):
        if run['stop_at'] is not None:
            return rlb1.GEN_STOPPED
        elapsed = mono - run['t0']
        if elapsed >= min(run['count'] * run['interval_ms'], 60_000):
            return rlb1.GEN_COMPLETE
        return rlb1.GEN_RUNNING

    def _gen_counters(self, run, mono):
        sent = min(run['count'],
                   max(0, (mono - run['t0']) // max(run['interval_ms'], 1)))
        # Delivered == sent: the fake destination counts every bound packet.
        self.bench_counts[(run['dst'], run['run_hex'])] = sent
        return {'planned': run['count'], 'submitted': sent, 'admitted': sent,
                'delivered': sent, 'failed': 0, 'unknown': 0,
                'first_ms': run['t0'] % (2**32),
                'last_ms': (run['t0'] + sent * run['interval_ms']) % (2**32)}

    def _admit(self, mono):
        self.tokens = min(self.BURST, self.tokens + (mono - self.tokens_at) * self.RATE_PER_MIN / 60_000)
        self.tokens_at = mono
        if self.tokens < 1:
            raise FakeMethodError('RATE_LIMITED', True, scope='principal',
                                  retry_after_ms=math.ceil((1 - self.tokens) * 60_000 / self.RATE_PER_MIN))
        self.tokens -= 1

    @staticmethod
    def _record(op, mono):
        age = mono - op['submitted']
        if age < 300:
            state = 'HOST_QUEUED'
        elif not op['reachable']:
            state = 'REJECTED_NOT_ACCEPTED'
        elif age < 900 or op['delivery'] == 'BEST_EFFORT':
            state = 'GATEWAY_ACCEPTED'
        else:
            state = 'END_SDK_RECEIVED'
        return {'operation_id': op['operation_id'], 'dispatch_state': state,
                'evidence': [], 'message_key': None, 'application_outcome': None}


def _status_body(result, state, counters=None):
    """PEER_SEND_STATUS body for the fake device's replies."""
    c = counters or {'planned': 0, 'submitted': 0, 'admitted': 0,
                     'delivered': 0, 'failed': 0, 'unknown': 0,
                     'first_ms': 0, 'last_ms': 0}
    return rlb1.encode_peer_send_status(
        {'result': result, 'state': state, **c})


def _hex(value, length):
    return (isinstance(value, str) and len(value) == length and
            all(char in '0123456789abcdefABCDEF' for char in value))


def _network(value):
    return _hex(value, 16) and 1 <= int(value, 16) <= 0xffffffff


def write_demo_capture(path, *, count=8, duration_s=120, step_ms=2000, capture_id='demo'):
    """Synthetic capture (gateway view + parent routes + RSSI samples) for replay demos."""
    clock = FakeClock(1_000_000_000, 1_790_000_000_000)
    mesh = DemoMesh(count, clock=lambda: (clock.mono_ns // 1_000_000, clock.unix_ms))
    seq = 0
    with Capture(path, capture_id, versions={'generator': 'routeloom_meshviz.demo'},
                 scopes=['demo']) as capture:
        for _ in range(duration_s * 1000 // step_ms):
            nodes = mesh.gateway_nodes()
            links, routes = mesh.observer_payload(clock.mono_ns)
            gateway_links = [{'observer': GATEWAY, 'peer': n['node'], 'rssi_dbm': n['rssi_dbm'],
                              'direction': 'peer_to_observer', 'evidence': 'gateway_neighbor'}
                             for n in nodes if n['neighbor']]
            gateway_routes = [{'observer': GATEWAY, 'destination': n['node'],
                               'next_hop': n['next_hop'], 'valid': n['connected'] is True,
                               'metric': n['route_metric']}
                              for n in nodes if n['node'] != GATEWAY and n['listed']]
            seq += 1
            capture.add({'kind': 'snapshot', 'scope': 'demo', 'source': 'demo', 'source_epoch': '1',
                         'source_seq': seq,
                         'payload': {'complete': True, 'nodes': nodes,
                                     'links': links + gateway_links,
                                     'routes': routes + gateway_routes}}, clock)
            for link in links:
                seq += 1
                capture.add({'kind': 'sample', 'scope': 'demo', 'source': 'demo', 'source_epoch': '1',
                             'source_seq': seq,
                             'payload': {'series': f'rssi_dbm/{link["peer"]}/{link["observer"]}',
                                         'value': link['rssi_dbm'], 'unit': 'dBm',
                                         'observed_unix_ms': clock.unix_ms}}, clock)
            clock.advance(step_ms)
    return path
