"""Qt-free API1 line codec and nodes.list → reducer event normalization.

The gateway view is all today's API1 exposes: the physical links it proves are the
gateway's direct neighbors, and its routes are logical next hops, never physical
edges. Values the daemon reports as null stay null (displayed as unknown).
"""
import json

REQUEST_MAX_BYTES = 8192
RESPONSE_MAX_BYTES = 65536
# Link fields that change with every poll without a new observation behind them.
_VOLATILE = ('heard_age_ms', 'updated_ms')


def encode_request(request_id: str, method: str, params: dict) -> bytes:
    line = b'API1 ' + json.dumps({'v': 1, 'request_id': request_id, 'method': method,
                                  'params': params}, separators=(',', ':')).encode() + b'\n'
    if len(line) > REQUEST_MAX_BYTES:
        raise ValueError('API1 request too long')
    return line


class LineDecoder:
    """Bounded newline framing; an oversized line is a protocol failure, not truncation."""
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[dict]:
        self.buffer.extend(data)
        replies = []
        while (end := self.buffer.find(b'\n')) >= 0:
            line = bytes(self.buffer[:end])
            del self.buffer[:end + 1]
            if len(line) > RESPONSE_MAX_BYTES:
                raise ValueError('API1 response too long')
            reply = json.loads(line)
            if not isinstance(reply, dict) or reply.get('v') != 1:
                raise ValueError('invalid API1 response')
            replies.append(reply)
        if len(self.buffer) > RESPONSE_MAX_BYTES:
            raise ValueError('API1 response too long')
        return replies


class NodesNormalizer:
    """Turns complete nodes.list listings into reducer events for one daemon connection."""
    def __init__(self, connection: int, source='api1'):
        self.source = source
        self.connection = connection
        self.session = object()
        self.generation = 0
        self.seq = 0
        self.last_content = None
        self.last_heard = {}
        self.last_emit_ms = None

    def events(self, source_info: dict, nodes: list, now_unix_ms: int, *, force_ms=30_000):
        session = source_info.get('session_id')
        if session != self.session:
            # A new gateway USB session (or its loss) retires the previous session's claims.
            self.session = session
            self.generation += 1
            self.last_content = None
            self.last_heard = {}
        epoch = f'c{self.connection}-g{self.generation}'
        gateway = source_info.get('gateway')
        scope = f'gw-{gateway}' if isinstance(gateway, str) and gateway else 'gw-unknown'
        items, links, routes = [], [], []
        for node in nodes:
            item = {key: value for key, value in node.items() if key not in _VOLATILE}
            item['clock'] = 'host_unix_ms'
            items.append(item)
            if not gateway or node.get('node') == gateway:
                continue
            if node.get('neighbor') is True or node.get('direct') is True:
                links.append({'observer': gateway, 'peer': node['node'],
                              'rssi_dbm': node.get('rssi_dbm'),
                              'rssi_avg_dbm': node.get('rssi_avg_dbm'),
                              'link_cost': node.get('link_cost'),
                              'direction': 'peer_to_observer', 'evidence': 'gateway_neighbor',
                              'observed_unix_ms': node.get('last_heard_ms')})
            if node.get('listed') is not False:
                # next_hop null on a listed node is an observed "no route", not missing data.
                routes.append({'observer': gateway, 'destination': node['node'],
                               'next_hop': node.get('next_hop'),
                               'metric': node.get('route_metric'),
                               'valid': node.get('connected') is True and node.get('next_hop') is not None,
                               'evidence': 'gateway_selected'})
        events = []
        content = json.dumps([items, links, routes], sort_keys=True)
        if (content != self.last_content or self.last_emit_ms is None or
                now_unix_ms - self.last_emit_ms >= force_ms):
            self.seq += 1
            events.append({'kind': 'snapshot', 'scope': scope, 'source': self.source,
                           'source_epoch': epoch, 'source_seq': self.seq,
                           'payload': {'complete': True, 'nodes': items, 'links': links,
                                       'routes': routes, 'source_state': source_info.get('state'),
                                       'received_unix_ms': now_unix_ms}})
            self.last_content = content
            self.last_emit_ms = now_unix_ms
        for link in links:
            heard = link['observed_unix_ms']
            if self.last_heard.get(link['peer']) == heard:
                continue
            self.last_heard[link['peer']] = heard
            self.seq += 1
            events.append({'kind': 'sample', 'scope': scope, 'source': self.source,
                           'source_epoch': epoch, 'source_seq': self.seq,
                           'payload': {'series': f'rssi_dbm/{link["peer"]}/{gateway}',
                                       'value': link['rssi_dbm'], 'unit': 'dBm',
                                       'observed_unix_ms': heard,
                                       'received_unix_ms': now_unix_ms}})
        return events
