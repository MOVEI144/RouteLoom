"""Qt-free, source-scoped observation reducer. Missing evidence remains unknown."""
from copy import deepcopy
from dataclasses import dataclass, field


@dataclass
class FakeClock:
    mono_ns: int = 0
    unix_ms: int = 0

    def __post_init__(self):
        if type(self.mono_ns) is not int or type(self.unix_ms) is not int:
            raise ValueError('clock values must be integer')

    def advance(self, ms: int):
        if type(ms) is not int or ms < 0:
            raise ValueError('monotonic time requires nonnegative integer milliseconds')
        self.mono_ns += ms * 1_000_000
        self.unix_ms += ms

    def jump_unix(self, ms: int):
        if type(ms) is not int:
            raise ValueError('wall-clock adjustment must be integer milliseconds')
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
    boot_history: dict = field(default_factory=dict)
    claims: dict = field(default_factory=dict)
    order: int = 0
    extensions: dict = field(default_factory=dict)


def reduce(state: State, event: dict) -> State:
    kind = event['kind']
    source = event['source']
    declared_epoch = event.get('source_epoch')
    seq = event.get('source_seq')
    previous = state.sources.get(source)
    epoch = declared_epoch if declared_epoch is not None else previous[0] if previous else None
    if declared_epoch is not None and epoch in state.retired_epochs.get(source, set()):
        return state
    if (previous and epoch == previous[0] and seq is not None and
            previous[1] is not None and seq <= previous[1]):
        return state
    if previous and declared_epoch is not None and epoch != previous[0]:
        if previous[0] is not None:
            state.retired_epochs.setdefault(source, set()).add(previous[0])
        # A new daemon session cannot keep the previous session's live claims.
        for section, table in (('nodes', state.nodes), ('links', state.links),
                               ('routes', state.routes), ('samples', state.samples)):
            for key in set(state.claims.get(section, {})) | set(table):
                entries = _claims(state, section, table, key)
                if source in entries:
                    del entries[source]
                    _refresh(state, section, table, key)
        state.boot_history.pop(source, None)
    state.sources[source] = (epoch, seq if seq is not None else
                             previous[1] if previous and epoch == previous[0] else None)
    if kind == 'clock_adjustment':
        state.clock_adjustments.append(event['payload']['delta_ms'])
        return state
    if kind == 'gap':
        state.gaps.append(deepcopy(event['payload']))
        return state
    scope = event.get('scope')
    if kind in ('snapshot', 'node', 'link', 'route', 'sample') and (
            not isinstance(scope, str) or not scope or ':' in scope):
        raise ValueError('invalid observation scope')
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
                _update(state, section, table, key, item, source)
            if payload.get('complete'):
                for key in set(state.claims.get(section, {})) | set(table):
                    if key.startswith(scope + ':') and key not in keys:
                        entries = _claims(state, section, table, key)
                        if source in entries:
                            del entries[source]
                            _refresh(state, section, table, key)
    elif kind in ('node', 'link', 'route'):
        table = {'node': state.nodes, 'link': state.links, 'route': state.routes}[kind]
        item = event['payload']
        key = _key(scope, kind + 's', item)
        if item.get('removed'):
            entries = _claims(state, kind + 's', table, key)
            old = entries.get(source)
            # A delayed removal from an earlier boot cannot retire a newer incarnation.
            if old and _boot(item) == _boot(old):
                del entries[source]
                _refresh(state, kind + 's', table, key)
            elif not entries:
                _refresh(state, kind + 's', table, key)
        else:
            _update(state, kind + 's', table, key, item, source)
    elif kind == 'sample':
        key = f"{scope}:{event['payload']['series']}"
        entries = _claims(state, 'samples', state.samples, key)
        state.order += 1
        entries[source] = {**deepcopy(event['payload']), '_source': source,
                           '_order': state.order}
        _refresh(state, 'samples', state.samples, key)
    return state


def _key(scope, section, item):
    fields = {'nodes': ('node',), 'links': ('observer', 'peer'),
              'routes': ('observer', 'destination')}[section]
    parts = [item[field] for field in fields]
    if any(not isinstance(part, str) or not part or ':' in part for part in parts):
        raise ValueError('invalid observation identity')
    return ':'.join((scope, *parts))


def _boot(item):
    boot = item.get('boot')
    if boot == 0 or isinstance(boot, str) and boot and set(boot) == {'0'}:
        return None
    return boot


def _claims(state, section, table, key):
    entries = state.claims.setdefault(section, {}).setdefault(key, {})
    if not entries and key in table and table[key].get('_source') is not None:
        legacy = table[key]
        entries[legacy['_source']] = {**legacy, '_order': legacy.get('_order', 0)}
    return entries


def _refresh(state, section, table, key):
    entries = state.claims[section][key]
    if entries:
        table[key] = max(entries.values(), key=lambda value: value['_order'])
    else:
        table.pop(key, None)
        del state.claims[section][key]


def _update(state, section, table, key, item, source):
    entries = _claims(state, section, table, key)
    old = entries.get(source)
    boot = _boot(item)
    old_boot = _boot(old) if old else None
    if old_boot is not None and boot is None:
        return
    boots = list(state.boot_history.get(source, {}).get(section, {}).get(key, []))
    if old:
        boots = list(dict.fromkeys([*boots, *old.get('_old_boots', [])]))
    # Old boot observations cannot overwrite a newer incarnation even if delayed.
    if boot in boots and (not old or boot != old_boot):
        return
    if old_boot is not None and boot != old_boot:
        if old_boot not in boots:
            boots.append(old_boot)
    if boots:
        state.boot_history.setdefault(source, {}).setdefault(section, {})[key] = boots
    state.order += 1
    normalized = deepcopy(item)
    if 'boot' in normalized and boot is None:
        normalized['boot'] = None
    entries[source] = {**normalized, '_source': source, '_old_boots': boots,
                       '_order': state.order}
    _refresh(state, section, table, key)


def route_hops(state: State, scope: str, origin: str, destination: str,
               *, now_mono_ns: int | None = None, max_age_ns: int | None = None,
               max_skew_ns: int | None = None) -> int | None:
    """A selected route is logical, not proof of a physical hop; loops stay unknown."""
    if origin == destination:
        return 0
    if any(not isinstance(part, str) or ':' in part for part in (scope, origin, destination)):
        return None
    if (now_mono_ns is None or max_age_ns is None or max_skew_ns is None or
            max_age_ns < 0 or max_skew_ns < 0):
        return None
    seen = set()
    oldest = now_mono_ns
    newest = 0
    at = origin
    for hops in range(101):
        if at == destination:
            return hops
        if at in seen:
            return None
        seen.add(at)
        route = state.routes.get(f'{scope}:{at}:{destination}')
        if not route or route.get('valid') is not True or route.get('stale') or not route.get('next_hop'):
            return None
        sampled = route.get('sample_mono_ns')
        if type(sampled) is not int or sampled > now_mono_ns or now_mono_ns - sampled > max_age_ns:
            return None
        oldest = min(oldest, sampled)
        newest = max(newest, sampled)
        if newest - oldest > max_skew_ns:
            return None
        at = route['next_hop']
    return None
