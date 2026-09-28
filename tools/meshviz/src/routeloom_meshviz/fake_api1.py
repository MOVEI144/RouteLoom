"""In-memory API1 line server for Qt/USB-free contract fixtures."""
import json
import socketserver
import threading
from contextlib import contextmanager

from .demo import FakeMethodError


class FakeAPI1:
    def __init__(self, nodes=(), *, mesh=None, observation=None):
        self.buffer = bytearray()
        self.static_nodes = sorted(nodes, key=lambda node: node['node'])
        # Optional live scenario (demo.DemoMesh): changing node table plus a bounded
        # send subset. Without it the server answers only the read-only methods.
        self.mesh = mesh
        # Optional observation fixture: {'gateway', 'boot', 'session_id', 'sections',
        # 'routes'}. Serves health.get/topology.get with the daemon's param
        # contract (local-only observer, routes paging, exact present flag).
        self.observation = observation

    @property
    def nodes(self):
        if self.mesh is None:
            return self.static_nodes
        return sorted(self.mesh.gateway_nodes(), key=lambda node: node['node'])

    def feed(self, data: bytes) -> list[bytes]:
        replies = []
        for chunk in data.split(b'\n')[:-1]:
            if len(self.buffer) + len(chunk) + 1 > 8192:
                raise ValueError('API1 line too long')
            self.buffer.extend(chunk)
            replies.append(self._reply(bytes(self.buffer)))
            self.buffer.clear()
        tail = data.rsplit(b'\n', 1)[-1]
        if len(self.buffer) + len(tail) >= 8192:
            raise ValueError('API1 line too long')
        self.buffer.extend(tail)
        return replies

    def _reply(self, line: bytes) -> bytes:
        if not line.startswith(b'API1 '):
            raise ValueError('invalid API1 line')
        try:
            request = json.loads(line[5:].decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._error(None, 'INVALID_REQUEST')
        if not isinstance(request, dict):
            return self._error(None, 'INVALID_REQUEST')
        request_id = request.get('request_id')
        if (set(request) - {'v', 'request_id', 'method', 'params'} or
                type(request.get('v')) is not int or request['v'] != 1 or
                not isinstance(request_id, str) or not 1 <= len(request_id) <= 64 or
                not all(' ' <= char <= '~' for char in request_id) or
                not isinstance(request.get('method'), str)):
            return self._error(request_id, 'INVALID_REQUEST')
        params = request.get('params')
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return self._error(request_id, 'INVALID_REQUEST')
        if request['method'] == 'capabilities.get':
            if params:
                return self._error(request_id, 'INVALID_ARGUMENT')
            methods = {'capabilities.get': True, 'nodes.list': True}
            if self.observation is not None:
                methods.update({'health.get': True, 'topology.get': True})
            methods.update({method: True for method in
                            (self.mesh.METHODS if self.mesh is not None else ())})
            result = {'api': {'version': 1, 'request_max_bytes': 8192,
                              'response_max_bytes': 65536, 'max_depth': 8},
                      'methods': methods,
                      'nodes': {'page_max': 128, 'clock': 'host_unix_ms'},
                      'caps_version': 2}
        elif request['method'] == 'nodes.list':
            if set(params) - {'after', 'limit', 'connected'}:
                return self._error(request_id, 'INVALID_ARGUMENT')
            limit = params.get('limit', 128)
            after = params.get('after')
            connected = params.get('connected')
            if (type(limit) is not int or not 1 <= limit <= 128 or
                    after is not None and (not isinstance(after, str) or len(after) != 16 or
                                           any(char not in '0123456789abcdefABCDEF' for char in after)) or
                    connected is not None and type(connected) is not bool):
                return self._error(request_id, 'INVALID_ARGUMENT')
            if after is not None:
                after = after.lower()
            nodes = self.nodes
            selected = [node for node in nodes
                        if (after is None or node['node'] > after) and
                        (connected is None or node.get('connected') is connected)]
            page = selected[:limit]
            live = self.mesh is not None
            result = {'source': {'state': 'live', 'gateway': self.mesh.ids[0] if live else None,
                                 'session_id': 1 if live else None,
                                 'synced_ms': None, 'tracked': len(nodes), 'evicted': 0,
                                 'clock': 'host_unix_ms'},
                      'nodes': page,
                      'next_after': page[-1]['node'] if len(selected) > limit else None}
        elif request['method'] in ('health.get', 'topology.get'):
            if self.observation is None:
                return self._error(request_id, 'UNKNOWN_METHOD')
            outcome = self._observation(request_id, request['method'], params)
            if isinstance(outcome, bytes):
                return outcome
            result = outcome
        elif self.mesh is not None and request['method'] in self.mesh.METHODS:
            try:
                result = self.mesh.handle(request['method'], params)
            except FakeMethodError as exc:
                return self._error(request_id, exc.code, exc.detail, exc.retryable)
        else:
            return self._error(request_id, 'UNKNOWN_METHOD')
        return self._encode({'v': 1, 'request_id': request_id, 'ok': True, 'result': result})

    @staticmethod
    def _is_hex16(value):
        return (isinstance(value, str) and len(value) == 16 and
                all(char in '0123456789abcdefABCDEF' for char in value))

    def _observation(self, request_id, method, params):
        """Static observation fixture with the daemon's param contract."""
        fix = self.observation
        gateway = fix['gateway']
        known = {'observer', 'section', 'network', 'max_age_ms', 'subscribe'}
        if method == 'topology.get':
            known |= {'destination', 'cursor'}
        if set(params) - known:
            return self._error(request_id, 'INVALID_ARGUMENT')
        observer = params.get('observer')
        if not self._is_hex16(observer):
            return self._error(request_id, 'INVALID_ARGUMENT')
        if observer.lower() != gateway:
            return self._error(request_id, 'NOT_FOUND', {'reason': 'remote_not_served'})
        max_age_ms = params.get('max_age_ms')
        if max_age_ms is not None and (type(max_age_ms) is not int or
                                       not 0 <= max_age_ms <= 60_000):
            return self._error(request_id, 'INVALID_ARGUMENT')
        if params.get('subscribe') is not None and type(params['subscribe']) is not bool:
            return self._error(request_id, 'INVALID_ARGUMENT')
        network = params.get('network')
        if network is not None and not self._is_hex16(network):
            return self._error(request_id, 'INVALID_ARGUMENT')
        source = {'gateway': gateway, 'usb_session': fix['session_id'], 'observer': gateway,
                  'observer_boot': fix['boot'], 'transport': 'usb_local'}
        if method == 'health.get':
            section = params.get('section', 'system')
            if section not in ('system', 'tables', 'milestones'):
                return self._error(request_id, 'INVALID_ARGUMENT')
            return {'outcome': 'snapshot', 'scope': {'observer': gateway},
                    'snapshot': {'schema': 1, 'section': section, 'source': source,
                                 'revision': 0, 'received_unix_ms': 1000, 'age_ms': 0,
                                 'stale': False, 'complete': True, 'armed': False,
                                 section: fix['sections'][section]}}
        section = params.get('section')
        if section not in ('routes', 'neighbors', 'summary'):
            return self._error(request_id, 'INVALID_ARGUMENT')
        destination = params.get('destination')
        cursor = params.get('cursor')
        if destination is not None and cursor is not None:
            return self._error(request_id, 'INVALID_ARGUMENT')
        if destination is not None and (
                not self._is_hex16(destination) or
                destination.lower() in ('0000000000000000', 'ffffffffffffffff')):
            return self._error(request_id, 'INVALID_ARGUMENT')
        after = None
        if cursor is not None:
            parts = cursor.split('.') if isinstance(cursor, str) else []
            if (len(parts) != 7 or not self._is_hex16(parts[0]) or
                    parts[0].lower() == 'ffffffffffffffff' or
                    len(parts[1]) != 8 or
                    any(char not in '0123456789abcdefABCDEF' for char in parts[1]) or
                    any(not self._is_hex16(part) for part in parts[2:6]) or
                    len(parts[6]) != 2 or
                    any(char not in '0123456789abcdefABCDEF' for char in parts[6])):
                return self._error(request_id, 'INVALID_ARGUMENT')
            after = parts[0].lower()
        if section not in ('routes', 'neighbors') and (
                destination is not None or cursor is not None):
            return self._error(request_id, 'INVALID_ARGUMENT')
        snapshot = {'schema': 1, 'section': section, 'source': source,
                    'revision': fix.get('revision', 0), 'received_unix_ms': 1000,
                    'age_ms': 0, 'stale': False, 'armed': False}
        section_id = 4 if section == 'routes' else 5
        if cursor is not None and (
                parts[1].lower() != f"{snapshot['revision']:08x}" or
                parts[2].lower() != fix['boot'] or
                parts[3].lower() != fix['boot'] or
                parts[4].lower() != f"{fix['session_id']:016x}" or
                parts[5].lower() != gateway or
                parts[6].lower() != f"{section_id:02x}"):
            return self._error(request_id, 'SNAPSHOT_CHANGED', retryable=True)
        if section == 'summary':
            snapshot.update({'complete': True, 'summary': fix['sections']['summary'],
                             'entries': [], 'next_cursor': None})
            return {'outcome': 'snapshot', 'scope': {'observer': gateway}, 'snapshot': snapshot}
        key = 'destination' if section == 'routes' else 'peer'
        rows = sorted(fix['routes'] if section == 'routes' else fix.get('neighbors', []),
                      key=lambda entry: entry[key])
        if destination is not None:
            entries = [entry for entry in rows if entry[key] == destination.lower()]
            snapshot.update({'complete': True, 'present': bool(entries),
                             'entries': entries, 'next_cursor': None})
            return {'outcome': 'snapshot', 'scope': {'observer': gateway}, 'snapshot': snapshot}
        rest = [entry for entry in rows if after is None or entry[key] > after]
        page, more = rest[:8], len(rest) > 8
        next_cursor = (f"{page[-1][key]}.{snapshot['revision']:08x}.{fix['boot']}."
                       f"{fix['boot']}.{fix['session_id']:016x}.{gateway}.{section_id:02x}"
                       if more else None)
        snapshot.update({'complete': not more, 'entries': page,
                         'next_cursor': next_cursor})
        return {'outcome': 'snapshot', 'scope': {'observer': gateway}, 'snapshot': snapshot}

    def _error(self, request_id, code, detail=None, retryable=False):
        return self._encode({'v': 1, 'request_id': request_id if isinstance(request_id, str) else None,
                             'ok': False, 'error': {'code': code,
                                                    'detail': {'message': code, **(detail or {})},
                                                    'retryable': retryable}})

    @staticmethod
    def _encode(reply):
        encoded = json.dumps(reply, separators=(',', ':')).encode() + b'\n'
        if len(encoded) > 65536:
            raise ValueError('API1 response too long')
        return encoded


@contextmanager
def serve_fake_api1(path, nodes=(), *, mesh=None):
    """Local test server; no USB, daemon or Qt imports."""
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            protocol = FakeAPI1(nodes, mesh=mesh)
            try:
                while chunk := self.request.recv(4096):
                    for reply in protocol.feed(chunk):
                        self.request.sendall(reply)
            except (ConnectionResetError, BrokenPipeError):
                pass

    with socketserver.ThreadingUnixStreamServer(str(path), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()
