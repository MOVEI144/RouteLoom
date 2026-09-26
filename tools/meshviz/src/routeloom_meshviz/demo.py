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
    METHODS = ('operations.open_epoch', 'messages.submit', 'operations.get')
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
            if not _hex(network, 16):
                raise FakeMethodError('INVALID_ARGUMENT')
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
                    not _hex(destination.get('id'), 16) or not isinstance(payload, str) or
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
            return self._record(self.ops[op_id], mono)

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


def _hex(value, length):
    return (isinstance(value, str) and len(value) == length and
            all(char in '0123456789abcdefABCDEF' for char in value))


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
