"""Qt-free, source-scoped observation reducer. Missing evidence remains unknown."""
from dataclasses import dataclass, field


@dataclass
class FakeClock:
    mono_ns: int = 0
    unix_ms: int = 0

    def advance(self, ms: int):
        if ms < 0:
            raise ValueError('monotonic time cannot move backwards')
        self.mono_ns += ms * 1_000_000
        self.unix_ms += ms

    def jump_unix(self, ms: int):
        self.unix_ms += ms


@dataclass
class State:
    nodes: dict = field(default_factory=dict)
    links: dict = field(default_factory=dict)
    routes: dict = field(default_factory=dict)
    samples: dict = field(default_factory=dict)
    gaps: list = field(default_factory=list)
    clock_adjustments: list = field(default_factory=list)
    sources: dict = field(default_factory=dict)
    retired_epochs: dict = field(default_factory=dict)


def reduce(state: State, event: dict) -> State:
    kind = event['kind']
    if kind == 'clock_adjustment':
        state.clock_adjustments.append(event['payload']['delta_ms'])
        return state
    source = event['source']
    epoch = event.get('source_epoch')
    seq = event.get('source_seq')
    previous = state.sources.get(source)
    if epoch is not None and epoch in state.retired_epochs.get(source, set()):
        return state
    if previous and epoch == previous[0] and seq is not None and seq <= previous[1]:
        return state
    if previous and epoch is not None and epoch != previous[0]:
        state.retired_epochs.setdefault(source, set()).add(previous[0])
        # A new daemon session cannot keep the previous session's live claims.
        for table in (state.nodes, state.links, state.routes):
            for key in [k for k, v in table.items() if v.get('_source') == source]:
                del table[key]
    if seq is not None:
        state.sources[source] = (epoch, seq)
    if kind == 'gap':
        state.gaps.append(event['payload'])
        return state
    scope = event.get('scope')
    if kind == 'snapshot':
        payload = event['payload']
        for section, table in (('nodes', state.nodes), ('links', state.links), ('routes', state.routes)):
            entries = payload.get(section)
            if entries is None:
                continue
            keys = set()
            for item in entries:
                key = _key(scope, section, item)
                keys.add(key)
                _update(table, key, item, source)
            if payload.get('complete'):
                for key in [k for k, v in table.items() if k.startswith(scope + ':') and
                            v.get('_source') == source and k not in keys]:
                    del table[key]
    elif kind in ('node', 'link', 'route'):
        table = {'node': state.nodes, 'link': state.links, 'route': state.routes}[kind]
        item = event['payload']
        key = _key(scope, kind + 's', item)
        if item.get('removed'):
            table.pop(key, None)
        else:
            _update(table, key, item, source)
    elif kind == 'sample':
        state.samples[f"{scope}:{event['payload']['series']}"] = event['payload']
    return state


def _key(scope, section, item):
    fields = {'nodes': ('node',), 'links': ('observer', 'peer'),
              'routes': ('observer', 'destination')}[section]
    return ':'.join((scope, *(str(item[f]) for f in fields)))


def _update(table, key, item, source):
    old = table.get(key)
    # Old boot observations cannot overwrite a newer incarnation even if delayed.
    if old and item.get('boot') != old.get('boot') and item.get('boot') in old.get('_old_boots', []):
        return
    boots = list(old.get('_old_boots', [])) if old else []
    if old and old.get('boot') is not None and item.get('boot') != old.get('boot'):
        boots.append(old['boot'])
    table[key] = {**item, '_source': source, '_old_boots': boots}


def route_hops(state: State, scope: str, origin: str, destination: str) -> int | None:
    """A selected route is logical, not proof of a physical hop; loops stay unknown."""
    seen = set()
    at = origin
    for hops in range(101):
        if at == destination:
            return hops
        if at in seen:
            return None
        seen.add(at)
        route = state.routes.get(f'{scope}:{at}:{destination}')
        if not route or not route.get('valid') or not route.get('next_hop'):
            return None
        at = route['next_hop']
    return None
