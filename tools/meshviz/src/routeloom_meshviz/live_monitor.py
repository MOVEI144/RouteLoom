"""Qt-free live-monitor data layer: site reads, join timeline and rollcall summary.

Every milestone is a separate nullable field backed by its own evidence
(design-devflow §7.2). Nothing is inferred from USB attachment, first sighting,
group totals or another milestone; missing evidence stays None and renders as
an empty cell. Reads go through the API thread as tagged requests; this module
only schedules them and validates the replies.
"""
from dataclasses import dataclass, field
import math

# Join milestones in display order (§7.2). The order is for columns only:
# timestamps are never forced into this sequence.
MILESTONES = ('power_on_at', 'boot_at', 'join_started_at', 'request_verified_at',
              'approval_committed_at', 'member_adopted_at', 'confirmed_at',
              'first_rollcall_rx_at', 'first_response_observed_at', 'route_first_at',
              'route_stable_at')
MILESTONE_LABELS = {
    'power_on_at': '電源 ON', 'boot_at': 'boot', 'join_started_at': 'Join 開始',
    'request_verified_at': '検証済み申請', 'approval_committed_at': '承認 commit',
    'member_adopted_at': 'RLS1 採用', 'confirmed_at': 'JoinConfirm',
    'first_rollcall_rx_at': '初回点呼受信', 'first_response_observed_at': '初回 STATUS',
    'route_first_at': '経路初観測', 'route_stable_at': '経路安定を観測'}
# Device-side milestones need a device→host clock mapping (D05); they are only
# accepted when the source already reports them on the host clock.
DEVICE_MILESTONES = ('boot_at', 'join_started_at', 'member_adopted_at', 'first_rollcall_rx_at')

# Participation states for colouring and animation (§7.1). 観測のみ is a node the
# gateway sees without any ledger evidence: never drawn in a Member colour.
JOIN_STATES = ('未参加', '観測のみ', '検証済申請', '承認', 'Member', '到達可能', '除外')

# Initial route-stability rule (§7.2): the same valid next hop in this many
# consecutive gateway snapshots spanning at least this long, with an app
# response observed inside the span.
ROUTE_STABLE_SNAPSHOTS = 3
ROUTE_STABLE_NS = 5_000_000_000
MAX_ROWS = 1024
MAX_MARKERS = 64

# Rollcall airtime budget (§6.5): LR250 model shared with the SDK estimator.
FRAME_OVERHEAD_B = 96
US_PER_BYTE = 32
ROUND_US_PER_NODE = 15_296
MIN_INTERVAL_MS = 2000
ROLLCALL_BUDGET_US_PER_S = 100_000
RETRY_FACTOR = 1.5


def rollcall_round_us(nodes):
    """Loss-free GROUP_DATA + GROUP_REPORT airtime of one round for N nodes (root included)."""
    if type(nodes) is not int or nodes < 1:
        raise ValueError('node count must be a positive integer')
    return (nodes - 1) * ROUND_US_PER_NODE


def rollcall_interval_floor_ms(nodes, *, budget_us_per_s=ROLLCALL_BUDGET_US_PER_S,
                               retry_factor=RETRY_FACTOR):
    """T_budget = max(2 s, retry × C_round(N) / B). 2 s is a start-interval floor, not an SLA."""
    if budget_us_per_s <= 0 or retry_factor < 1:
        raise ValueError('budget must be positive and retry factor at least 1')
    needed_ms = retry_factor * rollcall_round_us(nodes) * 1000 / budget_us_per_s
    return max(MIN_INTERVAL_MS, math.ceil(needed_ms))


def _int(value):
    return value if type(value) is int else None


def _str(value):
    return value if isinstance(value, str) and value else None


@dataclass
class Evidence:
    at_unix_ms: int
    source: str
    detail: str = ''
    estimated: bool = False


@dataclass
class JoinRow:
    node: str
    kid: str | None = None
    fields: dict = field(default_factory=dict)
    ledger_state: str | None = None
    confirm_state: str | None = None
    requested: bool = False
    removed: bool = False
    observed: bool = False
    reachable: bool | None = None
    next_hop: str | None = None
    route_streak: list = field(default_factory=list)
    join_proxy: str | None = None
    last_status_unix_ms: int | None = None
    response_mono_ns: list = field(default_factory=list)
    identity_changes: int = 0

    def state(self):
        if self.removed:
            return '除外'
        if self.ledger_state == 'member':
            if self.reachable and self.fields.get('confirmed_at') is not None:
                return '到達可能'
            if self.fields.get('confirmed_at') is not None or self.confirm_state == 'active':
                return 'Member'
            return '承認'
        if self.requested:
            return '検証済申請'
        return '観測のみ' if self.observed else '未参加'


class JoinTimeline:
    """Per-device milestone table. First evidence wins; a new kid starts a fresh row."""
    def __init__(self, max_rows=MAX_ROWS):
        self.rows = {}
        self.max_rows = max_rows
        self.truncated = False
        self.session = None
        self.markers = []

    def _row(self, node, kid=None):
        if not _is_node(node):
            return None
        row = self.rows.get(node)
        if row is None:
            if len(self.rows) >= self.max_rows:
                self.truncated = True
                return None
            row = self.rows[node] = JoinRow(node)
        if kid is not None and row.kid is not None and kid != row.kid:
            # A different identity for the same NodeId is a new device incarnation;
            # the previous identity's times must not describe it.
            fresh = JoinRow(node, kid, identity_changes=row.identity_changes + 1)
            self.rows[node] = row = fresh
        if kid is not None:
            row.kid = kid
        return row

    def _set(self, row, name, evidence, changed):
        if row is None or evidence is None or type(evidence.at_unix_ms) is not int:
            return
        if row.fields.get(name) is None:
            row.fields[name] = evidence
            changed.append({'node': row.node, 'kid': row.kid, 'field': name,
                            'at_unix_ms': evidence.at_unix_ms, 'source': evidence.source,
                            'detail': evidence.detail, 'estimated': evidence.estimated})

    def begin_session(self, session):
        """A new API connection: route streaks and response windows do not carry over."""
        if session != self.session:
            self.session = session
            for row in self.rows.values():
                row.route_streak = []
                row.response_mono_ns = []
                row.reachable = None

    # --- authority ledger (site.status / join.requests.list / members.list) ---

    def on_requests(self, requests):
        changed = []
        for item in requests if isinstance(requests, list) else ():
            if not isinstance(item, dict):
                continue
            node, kid = item.get('device_id'), _str(item.get('kid'))
            active = self.rows.get(node)
            if active is not None and active.ledger_state is not None and active.kid != kid:
                continue
            row = self._row(node, kid)
            if row is None:
                continue
            row.requested = True
            via = item.get('via') if isinstance(item.get('via'), dict) else {}
            proxy = via.get('proxy')
            # The relay path is an unauthenticated routing fact: drawn as its own layer only.
            row.join_proxy = proxy if _is_node(proxy) and proxy != row.node and int(proxy, 16) else None
            created = _int(item.get('created_ms'))
            if created is not None:
                # The authority records a request only after DevCert/PoP verification.
                self._set(row, 'request_verified_at',
                          Evidence(created, 'authority', f'{item.get("join_request_id")} '
                                   f'attempt {item.get("attempt")}'), changed)
        return changed

    def on_members(self, members):
        changed = []
        for item in members if isinstance(members, list) else ():
            if not isinstance(item, dict):
                continue
            row = self._row(item.get('device_id'), _str(item.get('kid')))
            if row is None:
                continue
            row.ledger_state = _str(item.get('state'))
            row.confirm_state = _str(item.get('confirm_state'))
            row.removed = row.ledger_state == 'removed'
            generation = item.get('generation')
            approved = _int(item.get('approved_ms'))
            if approved is not None:
                self._set(row, 'approval_committed_at',
                          Evidence(approved, 'authority', f'ledger commit generation {generation}'),
                          changed)
            confirmed = _int(item.get('confirmed_ms'))
            if confirmed is not None:
                self._set(row, 'confirmed_at',
                          Evidence(confirmed, 'authority', 'JoinConfirm observed'), changed)
        return changed

    # --- gateway route observations (one per complete nodes.list poll) ---

    def on_routes(self, observation):
        """observation: {mono_ns, unix_ms, gateway, routes: {node: next_hop|None}, connected: {...}}."""
        changed = []
        mono = observation.get('mono_ns')
        unix = observation.get('unix_ms')
        gateway = observation.get('gateway')
        if type(mono) is not int or type(unix) is not int:
            return changed
        routes = observation.get('routes') or {}
        for node, next_hop in routes.items():
            if node == gateway:
                continue
            row = self.rows.get(node)
            if row is None:
                row = self._row(node)
                if row is None:
                    continue
            row.observed = True
            valid = isinstance(next_hop, str) and bool(next_hop)
            row.reachable = valid
            if not valid:
                row.next_hop = None
                row.route_streak = []
                continue
            if row.next_hop != next_hop:
                row.route_streak = []
            row.next_hop = next_hop
            row.route_streak.append(mono)
            row.route_streak = row.route_streak[-ROUTE_STABLE_SNAPSHOTS * 4:]
            self._set(row, 'route_first_at',
                      Evidence(unix, f'observer {gateway}', f'next hop {next_hop}'), changed)
            self._check_stable(row, unix, gateway, changed)
        for node, row in self.rows.items():
            if node not in routes and row.observed:
                row.reachable = None
                row.route_streak = []
        return changed

    def _check_stable(self, row, unix, observer, changed):
        streak = row.route_streak
        if len(streak) < ROUTE_STABLE_SNAPSHOTS or streak[-1] - streak[0] < ROUTE_STABLE_NS:
            return
        start = streak[0]
        if not any(start <= t <= streak[-1] for t in row.response_mono_ns):
            return
        self._set(row, 'route_stable_at',
                  Evidence(unix, f'observer {observer}',
                           f'next hop {row.next_hop}: {len(streak)} snapshots/'
                           f'{(streak[-1] - start) / 1e9:.1f} s + app response'), changed)

    # --- individual device STATUS via the rollcall service (D09) ---

    def on_statuses(self, statuses, mono_ns):
        changed = []
        for item in statuses if isinstance(statuses, list) else ():
            if not isinstance(item, dict):
                continue
            row = self._row(item.get('node'), _str(item.get('kid')))
            if row is None:
                continue
            first = _int(item.get('first_status_received_ms'))
            last = _int(item.get('last_status_received_ms'))
            if first is not None:
                self._set(row, 'first_response_observed_at',
                          Evidence(first, 'rollcall', 'individual STATUS received by PC'), changed)
            if last is not None and last != row.last_status_unix_ms:
                row.last_status_unix_ms = last
                row.response_mono_ns.append(mono_ns)
                row.response_mono_ns = row.response_mono_ns[-16:]
            milestones = item.get('milestones')
            for name in DEVICE_MILESTONES:
                value = milestones.get(name) if isinstance(milestones, dict) else None
                if isinstance(value, dict) and _int(value.get('at_unix_ms')) is not None:
                    self._set(row, name, Evidence(value['at_unix_ms'], 'device',
                                                  'host clock mapping',
                                                  value.get('estimated') is not False), changed)
        return changed

    def mark_power_on(self, node, unix_ms, operator='operator'):
        """Manual power marker: the operator's own record, precision is human."""
        if len(self.markers) >= MAX_MARKERS:
            return []
        changed = []
        row = self._row(node)
        self._set(row, 'power_on_at', Evidence(unix_ms, operator, 'manual marker'), changed)
        if changed:
            self.markers.append(changed[0])
        return changed

    def apply_recorded(self, milestone):
        """Replay: rebuild a row from a recorded milestone event, never from inference."""
        row = self._row(milestone.get('node'), _str(milestone.get('kid')))
        if row is None or milestone.get('field') not in MILESTONES:
            return
        at = _int(milestone.get('at_unix_ms'))
        if at is not None and row.fields.get(milestone['field']) is None:
            row.fields[milestone['field']] = Evidence(at, str(milestone.get('source')),
                                                      str(milestone.get('detail', '')),
                                                      milestone.get('estimated') is True)

    def states(self):
        return {node: row.state() for node, row in self.rows.items()}


def transitions(previous, current):
    """(node, before, after) for join-state changes; the animation draws only these."""
    return [(node, previous.get(node, '未参加'), state)
            for node, state in current.items() if previous.get(node, '未参加') != state]


def route_switches(previous, current):
    """(node, old_next_hop, new_next_hop) where an observed next hop changed."""
    return [(node, previous[node], hop) for node, hop in current.items()
            if previous.get(node) and hop and previous[node] != hop]


def _is_node(value):
    return (isinstance(value, str) and len(value) == 16 and
            all(char in '0123456789abcdef' for char in value))


# --- rollcall status normalisation ------------------------------------------------

ROLLCALL_COUNTS = ('inventory_planned', 'active_members', 'tree_explained', 'delivered',
                   'nonmember', 'missing', 'unaccounted')


def rollcall_summary(result):
    """lab.rollcall.status → display dict; absent or malformed values stay None (不明)."""
    if not isinstance(result, dict):
        return None
    counts = result.get('counts') if isinstance(result.get('counts'), dict) else {}
    return {
        'state': _str(result.get('state')),
        'run_id': _str(result.get('run_id')),
        'poll_seq': _int(result.get('poll_seq')),
        'roster_revision': _int(result.get('roster_revision')),
        'desired_interval_ms': _int(result.get('desired_interval_ms')),
        'effective_interval_ms': _int(result.get('effective_interval_ms')),
        'extension_reason': _str(result.get('extension_reason')),
        'settle_ms': _int(result.get('settle_ms')),
        'airtime_estimate_us_per_s': _int(result.get('airtime_estimate_us_per_s')),
        'airtime_observed_us_per_s': _int(result.get('airtime_observed_us_per_s')),
        'status_age_ms': _int(result.get('status_age_ms')),
        'lease_remaining_ms': _int(result.get('lease_remaining_ms')),
        'skipped': _int(result.get('skipped')),
        'counts': {key: _int(counts.get(key)) for key in ROLLCALL_COUNTS},
    }


# --- site reads ----------------------------------------------------------------------

SITE_READS = (
    ('site', 'site.status', 5_000),
    ('requests', 'join.requests.list', 2_000),
    ('members', 'members.list', 2_000),
    ('rollcall', 'lab.rollcall.status', 2_000),
    ('inventory', 'lab.inventory.list', 10_000),
)
REQUEST_TIMEOUT_MS = 10_000
MAX_MEMBER_PAGES = 8


class SitePoller:
    """Schedules the site/rollcall reads; replies are matched by tag and stale ones dropped.

    One read of each kind is in flight at a time. A connection change (reset)
    bumps the generation, so a reply from the previous daemon session cannot
    update the new one. Unsupported methods are displayed as 未対応; a
    retryable refusal waits retry_after_ms before the next attempt.
    """
    def __init__(self, prefix='site'):
        self.prefix = prefix
        self.generation = 0
        self.counter = 0
        self.reset()

    def reset(self, methods=None):
        self.generation += 1
        self.methods = dict(methods or {})
        self.outstanding = {}
        self.next_at = {}
        self.results = {}
        self.errors = {}
        self.member_pages = None
        self.followups = []
        self.connected = methods is not None

    def set_methods(self, methods):
        self.methods = dict(methods or {})

    def supported(self, method):
        return bool(self.methods.get(method))

    def due(self, now_ms):
        if not self.connected:
            return []
        for tag, (_, _, sent) in list(self.outstanding.items()):
            if now_ms - sent > REQUEST_TIMEOUT_MS:
                kind = self.outstanding.pop(tag)[0]
                self.errors[kind] = 'timeout'
                self.next_at[kind] = now_ms
        requests, self.followups = self.followups, []
        busy = {kind for kind, _, _ in self.outstanding.values()}
        for kind, method, period in SITE_READS:
            if kind in busy or now_ms < self.next_at.get(kind, 0):
                continue
            if not self.supported(method):
                self.errors[kind] = 'unsupported'
                continue
            params = {'limit': 128, 'include_removed': True} if kind == 'members' else {}
            if kind == 'members':
                self.member_pages = []
            requests.append(self._request(kind, method, params, now_ms))
            self.next_at[kind] = now_ms + period
        return requests

    def _request(self, kind, method, params, now_ms):
        self.counter += 1
        tag = f'{self.prefix}-{self.generation}-{self.counter}'
        self.outstanding[tag] = (kind, method, now_ms)
        return tag, method, params

    def owns(self, tag):
        return isinstance(tag, str) and tag.startswith(f'{self.prefix}-')

    def on_reply(self, tag, reply, now_ms):
        """→ (kind, result) for an accepted reply, None for stale/unknown/failed ones."""
        entry = self.outstanding.pop(tag, None)
        if entry is None:
            return None
        kind, method, _ = entry
        if reply is None:
            self.errors[kind] = '応答なし（不明）'
            return None
        if not reply.get('ok'):
            error = reply.get('error') or {}
            code = error.get('code')
            detail = error.get('detail') if isinstance(error.get('detail'), dict) else {}
            retry = detail.get('retry_after_ms')
            if code == 'UNKNOWN_METHOD':
                self.methods[method] = False
                self.errors[kind] = 'unsupported'
            elif code == 'SITE_AUTHORITY_UNAVAILABLE':
                self.errors[kind] = 'no_authority'
            elif code == 'AuthorizationFailed':
                self.errors[kind] = 'forbidden'
            else:
                self.errors[kind] = str(code)
            if type(retry) is int and retry > 0:
                # Honour the daemon's back-off instead of the normal period.
                self.next_at[kind] = max(self.next_at.get(kind, 0), now_ms + retry)
            self.member_pages = None if kind == 'members' else self.member_pages
            return None
        result = reply.get('result')
        if not isinstance(result, dict):
            self.errors[kind] = 'invalid'
            return None
        if kind == 'members':
            members = result.get('members')
            after = result.get('next_after')
            if (self.member_pages is None or not isinstance(members, list) or len(members) > 128
                    or len(self.member_pages) + len(members) > 128 * MAX_MEMBER_PAGES):
                self.errors[kind] = 'invalid'
                self.member_pages = None
                return None
            self.member_pages.extend(members)
            if after is not None:
                if not _is_node(after) or len(self.member_pages) >= 128 * MAX_MEMBER_PAGES:
                    self.errors[kind] = 'invalid'
                    self.member_pages = None
                    return None
                # The next page goes out on the next due(); pages of one listing
                # share the generation, so a reconnect discards the partial set.
                self.followups.append(self._request(
                    'members', 'members.list',
                    {'limit': 128, 'include_removed': True, 'after': after}, now_ms))
                return None
            result = {'members': self.member_pages}
            self.member_pages = None
        self.errors.pop(kind, None)
        self.results[kind] = (result, now_ms)
        return kind, result


ERROR_TEXT = {'unsupported': '未対応（daemon が広告していない）',
              'no_authority': '未対応（daemon に Site Authority なし）',
              'forbidden': '権限なし（ACL grant 不足）', 'timeout': '応答なし（不明）',
              'invalid': '応答不正（不明）'}


def read_status_text(poller, kind):
    """Display text for one read: 未対応/権限なし/不明 are distinct from an empty result."""
    error = poller.errors.get(kind)
    if not poller.connected:
        return '未接続'
    if error is not None:
        return ERROR_TEXT.get(error, f'失敗 {error}（不明）')
    if kind not in poller.results:
        return '未取得'
    return None
