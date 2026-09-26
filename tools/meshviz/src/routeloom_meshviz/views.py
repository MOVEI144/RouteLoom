"""Qt-free model → display conversion. Missing values render as 不明, never as 0."""
from dataclasses import dataclass, field

from .model import State, route_hops

UNKNOWN = '不明'
NOT_AVAILABLE = '未取得'
# Displayed freshness classes; protocol staleness (telemetry_stale) is a separate field.
FRESH_MS = 5_000
STALE_MS = 30_000
TREE_MAX_AGE_NS = 60_000_000_000
TREE_MAX_SKEW_NS = 30_000_000_000


def fmt(value, unit='', *, none=UNKNOWN):
    if value is None:
        return none
    if isinstance(value, bool):
        return 'はい' if value else 'いいえ'
    if isinstance(value, float):
        value = f'{value:.3g}'
    return f'{value} {unit}'.rstrip() if unit else str(value)


def fmt_rate(value):
    return UNKNOWN if value is None else f'{100 * value:.1f}%'


def fmt_age(now_ms, observed_ms):
    if type(observed_ms) is not int or type(now_ms) is not int:
        return UNKNOWN
    age = now_ms - observed_ms
    if age < 0:
        return '0.0 s'
    return f'{age / 1000:.1f} s' if age < 120_000 else f'{age // 60_000} 分'


def freshness(now_ms, observed_ms):
    if type(observed_ms) is not int or type(now_ms) is not int:
        return UNKNOWN
    age = now_ms - observed_ms
    return '最新' if age <= FRESH_MS else '遅延' if age <= STALE_MS else '古い'


def short_id(node):
    if not isinstance(node, str):
        return UNKNOWN
    stripped = node.lstrip('0')
    return stripped.rjust(2, '0') if len(stripped) <= 4 else '…' + node[-4:]


def participation(node):
    """Connectivity state only; Site membership is a separate, not-yet-available field."""
    if node is None:
        return UNKNOWN
    if node.get('listed') is False:
        return '消滅'
    connected = node.get('connected')
    if connected is True:
        return '接続'
    if connected is False:
        return '通信なし'
    return UNKNOWN


@dataclass
class TopologyModel:
    scope: str | None = None
    gateway: str | None = None
    nodes: dict = field(default_factory=dict)
    phys_edges: dict = field(default_factory=dict)
    route_edges: dict = field(default_factory=dict)
    tree_edges: dict = field(default_factory=dict)
    no_route: set = field(default_factory=set)


def _scoped(table, scope):
    prefix = scope + ':'
    return {key[len(prefix):]: value for key, value in table.items() if key.startswith(prefix)}


def scopes(state: State):
    found = {}
    for key in state.nodes:
        scope = key.split(':', 1)[0]
        found[scope] = found.get(scope, 0) + 1
    return sorted(found, key=lambda scope: (-found[scope], scope))


def topology(state: State, scope=None, *, now_mono_ns=None) -> TopologyModel:
    """Physical = observed neighbor, route = logical next hop, tree = node→gateway routes."""
    available = scopes(state)
    if scope is None or scope not in available:
        scope = available[0] if available else None
    model = TopologyModel(scope=scope)
    if scope is None:
        return model
    nodes = _scoped(state.nodes, scope)
    for key, item in nodes.items():
        if item.get('role') == 'gateway':
            model.gateway = key
    for key, item in nodes.items():
        hops = item.get('hops') if type(item.get('hops')) is int else None
        if hops is None and model.gateway:
            # Only a fresh, coherent route chain yields a hop count; metric is never converted.
            hops = route_hops(state, scope, key, model.gateway, now_mono_ns=now_mono_ns,
                              max_age_ns=TREE_MAX_AGE_NS, max_skew_ns=TREE_MAX_SKEW_NS)
        model.nodes[key] = {'id': key, 'label': short_id(key), 'role': item.get('role'),
                            'state': participation(item), 'hops': hops,
                            'last_heard_ms': item.get('last_heard_ms')}
    links = _scoped(state.links, scope)
    for key, link in links.items():
        observer, peer = key.split(':')
        pair = tuple(sorted((observer, peer)))
        edge = model.phys_edges.setdefault(pair, {'directions': set(), 'rssi_dbm': {}})
        edge['directions'].add((peer, observer))
        edge['rssi_dbm'][(peer, observer)] = link.get('rssi_dbm')
        for end in (observer, peer):
            model.nodes.setdefault(end, {'id': end, 'label': short_id(end), 'role': None,
                                         'state': UNKNOWN, 'hops': None, 'last_heard_ms': None})
    for edge in model.phys_edges.values():
        # Both directions observed is a confirmed bidirectional link; one side is not.
        edge['bidirectional'] = len(edge['directions']) == 2
    for key, route in _scoped(state.routes, scope).items():
        observer, destination = key.split(':')
        if route.get('valid') is not True or not route.get('next_hop'):
            if observer == model.gateway:
                model.no_route.add(destination)
            continue
        if destination == model.gateway and observer != model.gateway:
            model.tree_edges[observer] = route['next_hop']
        elif observer == model.gateway:
            model.route_edges[destination] = route['next_hop']
    return model


def path_to_gateway(model: TopologyModel, node):
    """Selected-route chain from node to gateway; stops at loops or missing data."""
    path, seen = [node], {node}
    while node != model.gateway and node in model.tree_edges and len(path) <= 100:
        node = model.tree_edges[node]
        if node in seen:
            break
        seen.add(node)
        path.append(node)
    return path


def quality_rows(state: State, scope, now_unix_ms, trial_by_destination=None):
    """Per-node gateway-view quality; heap/health is not exposed by API1 yet."""
    trial_by_destination = trial_by_destination or {}
    rows = []
    for key, item in sorted(_scoped(state.nodes, scope).items()):
        stats = trial_by_destination.get(key)
        heard = item.get('last_heard_ms')
        rows.append({
            'node': key, 'label': short_id(key), 'state': participation(item),
            'rssi': fmt(item.get('rssi_dbm'), 'dBm'),
            'rssi_avg': fmt(item.get('rssi_avg_dbm'), 'dBm'),
            'link_cost': fmt(item.get('link_cost')), 'route_metric': fmt(item.get('route_metric')),
            'hops': fmt(item.get('hops') if type(item.get('hops')) is int else None),
            'observed': fmt_age(now_unix_ms, heard), 'freshness': freshness(now_unix_ms, heard),
            'telemetry_stale': fmt(item.get('telemetry_stale')),
            'success': (f'{fmt_rate(stats["success_rate_min"])}〜{fmt_rate(stats["success_rate_max"])}'
                        if stats and stats['admitted'] else UNKNOWN),
            'latency_p50': fmt(stats['latency_ms']['p50'], 'ms') if stats else UNKNOWN,
            'heap': NOT_AVAILABLE,
        })
    return rows


def series_for(state: State, scope):
    return sorted(key[len(scope) + 1:] for key in state.samples if key.startswith(scope + ':'))
