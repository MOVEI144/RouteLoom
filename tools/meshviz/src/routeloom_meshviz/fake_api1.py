"""In-memory API1 line server for Qt/USB-free contract fixtures."""
import json
import socketserver
import threading
from contextlib import contextmanager


class FakeAPI1:
    def __init__(self, nodes=()):
        self.buffer = bytearray()
        self.nodes = sorted(nodes, key=lambda node: node['node'])

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
            result = {'api': {'version': 1, 'request_max_bytes': 8192,
                              'response_max_bytes': 65536, 'max_depth': 8},
                      'methods': {'capabilities.get': True, 'nodes.list': True},
                      'nodes': {'page_max': 128, 'clock': 'host_unix_ms'}}
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
            selected = [node for node in self.nodes
                        if (after is None or node['node'] > after) and
                        (connected is None or node.get('connected') is connected)]
            page = selected[:limit]
            result = {'source': {'state': 'live', 'gateway': None, 'session_id': None,
                                 'synced_ms': None, 'tracked': len(self.nodes), 'evicted': 0,
                                 'clock': 'host_unix_ms'},
                      'nodes': page,
                      'next_after': page[-1]['node'] if len(selected) > limit else None}
        else:
            return self._error(request_id, 'UNKNOWN_METHOD')
        return self._encode({'v': 1, 'request_id': request_id, 'ok': True, 'result': result})

    def _error(self, request_id, code):
        return self._encode({'v': 1, 'request_id': request_id if isinstance(request_id, str) else None,
                             'ok': False, 'error': {'code': code, 'detail': {'message': code},
                                                    'retryable': False}})

    @staticmethod
    def _encode(reply):
        encoded = json.dumps(reply, separators=(',', ':')).encode() + b'\n'
        if len(encoded) > 65536:
            raise ValueError('API1 response too long')
        return encoded


@contextmanager
def serve_fake_api1(path, nodes=()):
    """Local test server; no USB, daemon or Qt imports."""
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            protocol = FakeAPI1(nodes)
            while chunk := self.request.recv(4096):
                for reply in protocol.feed(chunk):
                    self.request.sendall(reply)

    with socketserver.ThreadingUnixStreamServer(str(path), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()
