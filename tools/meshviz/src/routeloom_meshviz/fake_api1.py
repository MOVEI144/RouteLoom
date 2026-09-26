"""In-memory API1 line server for Qt/USB-free contract fixtures."""
import json
import socketserver
import threading
from contextlib import contextmanager


class FakeAPI1:
    def __init__(self, nodes=()):
        self.buffer = bytearray()
        self.nodes = list(nodes)

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer.extend(data)
        if len(self.buffer) > 8192 and b'\n' not in self.buffer:
            raise ValueError('API1 line too long')
        replies = []
        while b'\n' in self.buffer:
            line, _, rest = self.buffer.partition(b'\n')
            self.buffer = bytearray(rest)
            if len(line) > 8192 or not line.startswith(b'API1 '):
                raise ValueError('invalid API1 line')
            request = json.loads(line[5:].decode('utf-8'))
            if request['v'] != 1:
                raise ValueError('unsupported API1 version')
            method = request['method']
            if method == 'capabilities.get':
                result = {'methods': ['nodes.list']}
            elif method == 'nodes.list':
                result = {'source': {'state': 'live'}, 'nodes': self.nodes, 'next_after': None}
            else:
                replies.append(json.dumps({'request_id': request['request_id'], 'ok': False,
                                           'error': {'code': 'UNSUPPORTED'}}).encode() + b'\n')
                continue
            replies.append(json.dumps({'request_id': request['request_id'], 'ok': True,
                                       'result': result}).encode() + b'\n')
        return replies


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
