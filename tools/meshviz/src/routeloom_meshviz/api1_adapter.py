"""Qt-free API1 line codec, observation queries, and nodes.list → reducer normalization.

The gateway view is all today's API1 exposes: the physical links it proves are the
gateway's direct neighbors, and its routes are logical next hops, never physical
edges. Values the daemon reports as null stay null (displayed as unknown).

Observation (health.get / topology.get) is local-only in M1: the observer must be
the attached gateway itself, and snapshots describe that one device — never the
mesh. Remote observers are refused by the daemon, never routed.
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


HEALTH_SECTIONS = ('system', 'tables', 'milestones')
TOPOLOGY_SECTIONS = ('routes', 'neighbors', 'summary')
OBSERVATION_MAX_AGE_MS = 60_000


def _node_id(value, name):
    if not isinstance(value, str) or len(value) != 16 or any(
            char not in '0123456789abcdefABCDEF' for char in value):
        raise ValueError(f'{name} must be a 16-hex node id')
    return value.lower()


def encode_health_request(request_id, observer, section='system', *, network=None,
                           max_age_ms=None, subscribe=False):
    """Builds one health.get line; only explicit options are sent."""
    if section not in HEALTH_SECTIONS:
        raise ValueError(f'section must be one of {HEALTH_SECTIONS}')
    params = {'observer': _node_id(observer, 'observer'), 'section': section}
    if network is not None:
        params['network'] = _node_id(network, 'network')
    if max_age_ms is not None:
        if type(max_age_ms) is not int or not 0 <= max_age_ms <= OBSERVATION_MAX_AGE_MS:
            raise ValueError('max_age_ms must be an integer 0..=60000')
        params['max_age_ms'] = max_age_ms
    if subscribe:
        params['subscribe'] = True
    return encode_request(request_id, 'health.get', params)


def encode_topology_request(request_id, observer, section, *, destination=None, cursor=None,
                             network=None, max_age_ms=None, subscribe=False):
    """Builds one topology.get line; only explicit options are sent."""
    if section not in TOPOLOGY_SECTIONS:
        raise ValueError(f'section must be one of {TOPOLOGY_SECTIONS}')
    params = {'observer': _node_id(observer, 'observer'), 'section': section}
    if destination is not None and cursor is not None:
        raise ValueError('destination and cursor are mutually exclusive')
    if destination is not None:
        params['destination'] = _node_id(destination, 'destination')
        if params['destination'] in ('0000000000000000', 'ffffffffffffffff'):
            raise ValueError('destination must be a non-reserved node id')
    if cursor is not None:
        params['cursor'] = _node_id(cursor, 'cursor')
        if params['cursor'] == 'ffffffffffffffff':
            raise ValueError('cursor must be below ffff…ffff')
    if section not in ('routes', 'neighbors') and (
            destination is not None or cursor is not None):
        raise ValueError('destination and cursor are routes/neighbors-only')
    if network is not None:
        params['network'] = _node_id(network, 'network')
    if max_age_ms is not None:
        if type(max_age_ms) is not int or not 0 <= max_age_ms <= OBSERVATION_MAX_AGE_MS:
            raise ValueError('max_age_ms must be an integer 0..=60000')
        params['max_age_ms'] = max_age_ms
    if subscribe:
        params['subscribe'] = True
    return encode_request(request_id, 'topology.get', params)


def parse_observation_snapshot(reply, section):
    """Unwraps one health.get/topology.get snapshot; the envelope is checked, not trusted.

    Returns the snapshot dict (source, revision, freshness plus the section body or
    route entries). A daemon error or a malformed envelope raises ValueError — the
    caller must not render a partial snapshot as a complete one.
    """
    if not isinstance(reply, dict) or reply.get('ok') is not True:
        error = reply.get('error') if isinstance(reply, dict) else None
        code = error.get('code') if isinstance(error, dict) else 'invalid reply'
        raise ValueError(f'observation query failed: {code}')
    result = reply.get('result')
    snapshot = result.get('snapshot') if isinstance(result, dict) else None
    if (not isinstance(result, dict) or result.get('outcome') != 'snapshot' or
            not isinstance(snapshot, dict) or snapshot.get('schema') != 1 or
            snapshot.get('section') != section or
            not isinstance(snapshot.get('source'), dict) or
            snapshot['source'].get('transport') != 'usb_local'):
        raise ValueError('malformed observation snapshot')
    return snapshot


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
            reply = json.loads(line, parse_constant=self._invalid_constant)
            if (not isinstance(reply, dict) or type(reply.get('v')) is not int or
                    reply['v'] != 1 or not isinstance(reply.get('request_id'), str) or
                    type(reply.get('ok')) is not bool or
                    not isinstance(reply.get('result' if reply['ok'] else 'error'), dict)):
                raise ValueError('invalid API1 response')
            replies.append(reply)
        if len(self.buffer) > RESPONSE_MAX_BYTES:
            raise ValueError('API1 response too long')
        return replies

    @staticmethod
    def _invalid_constant(value):
        raise ValueError(f'invalid JSON constant: {value}')


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
        session = (source_info.get('gateway'), source_info.get('session_id'))
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
