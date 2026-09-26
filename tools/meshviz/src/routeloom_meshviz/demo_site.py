"""Demo site for the fake API1 server: staggered joins, ledger reads and a fake rollcall.

Stands in for the Site Authority reads that exist on main (site.status,
join.requests.list, members.list) and for the methods that do not yet
(lab.inventory.list, lab.rollcall.* of D09), using the shapes the live monitor
consumes. Nothing here is evidence about a real device.
"""
from .demo import GATEWAY, DemoMesh, FakeMethodError
from .live_monitor import rollcall_interval_floor_ms

JOIN_STAGGER_MS = 300
VERIFY_MS, APPROVE_MS, CONFIRM_MS = 120, 220, 420
STATUS_DELAY_MS = 100
SITE_ID = 'a1b2c3d4e5f60718'
GW_ID = GATEWAY


class DemoSiteMesh(DemoMesh):
    METHODS = DemoMesh.METHODS + ('site.status', 'join.requests.list', 'members.list',
                                  'lab.inventory.list', 'lab.rollcall.status',
                                  'lab.rollcall.start', 'lab.rollcall.update', 'lab.rollcall.stop')

    def __init__(self, count=8, **kw):
        super().__init__(count, **kw)
        self.rollcall = None
        self.runs = 0

    def power_ms(self, node):
        """Elapsed ms at which the demo node is switched on (the gateway at 0)."""
        return 0 if node == GATEWAY else (self._index(node) - 1) * JOIN_STAGGER_MS

    def _confirmed(self, node, elapsed):
        return node == GATEWAY or elapsed >= self.power_ms(node) + CONFIRM_MS

    def gateway_nodes(self):
        # A node is not in the gateway table before its demo join completes.
        elapsed = self.clock()[0] - self.start_mono
        return [n for n in super().gateway_nodes() if self._confirmed(n['node'], elapsed)]

    def handle(self, method, params):
        if method in DemoMesh.METHODS:
            return super().handle(method, params)
        with self.lock:
            mono, unix = self.clock()
            elapsed = mono - self.start_mono
            if method == 'site.status':
                return self._status(elapsed, unix)
            if method == 'join.requests.list':
                return {'requests': self._requests(elapsed), 'max': 256, 'clock': 'host_unix_ms'}
            if method == 'members.list':
                after = params.get('after')
                members = [m for m in self._members(elapsed) if after is None or m['device_id'] > after]
                limit = params.get('limit', 128)
                page = members[:limit]
                return {'members': page, 'clock': 'host_unix_ms',
                        'next_after': page[-1]['device_id'] if len(members) > limit else None}
            if method == 'lab.inventory.list':
                return {'devices': [{'node_id': n, 'kid': self._kid(n), 'role': 'bridge' if n == GATEWAY
                                     else 'bench', 'board': f'demo-{n[-4:]}',
                                     'provision_state': 'provisioned', 'site': SITE_ID}
                                    for n in self.ids], 'revision': 1}
            return self._rollcall(method, params, elapsed)

    def _unix(self, elapsed):
        return self.start_unix + elapsed

    @staticmethod
    def _kid(node):
        return f'{int(node, 16):064x}'

    def _requests(self, elapsed):
        out = []
        for i, node in enumerate(self.ids[1:], 1):
            at = self.power_ms(node) + VERIFY_MS
            if elapsed < at:
                continue
            decided = elapsed >= self.power_ms(node) + APPROVE_MS
            out.append({'join_request_id': f'jr-{i:016x}', 'device_id': node, 'kid': self._kid(node),
                        'attempt': 1, 'created_ms': self._unix(at), 'updated_ms': self._unix(at),
                        'via': {'gateway': GW_ID, 'proxy': self._base_parent(node) or GW_ID,
                                'authority_hops': 1, 'joiner_rssi_dbm': -60},
                        'state': 'decided' if decided else 'awaiting',
                        'decision': {'verdict': 'allow', 'role': 'endpoint'} if decided else None})
        return out

    def _members(self, elapsed):
        out = []
        for node in self.ids:
            power = self.power_ms(node)
            if node != GATEWAY and elapsed < power + APPROVE_MS:
                continue
            confirmed = self._confirmed(node, elapsed)
            out.append({'device_id': node, 'kid': self._kid(node), 'state': 'member', 'generation': 1,
                        'role': 'gateway' if node == GATEWAY else 'endpoint',
                        'confirm_state': 'active' if confirmed else 'allowed_unconfirmed',
                        'approved_ms': self._unix(power + APPROVE_MS if node != GATEWAY else 0),
                        'confirmed_ms': self._unix(power + CONFIRM_MS if node != GATEWAY else 0)
                        if confirmed else None})
        return out

    def _status(self, elapsed, unix):
        members = self._members(elapsed)
        return {'site_id': SITE_ID, 'network': '000000000000a1b2', 'site_epoch': 1,
                'members': len(members),
                'members_unconfirmed': sum(m['confirm_state'] != 'active' for m in members),
                'join_requests': sum(r['state'] == 'awaiting' for r in self._requests(elapsed)),
                'authority': {'attached': True, 'channels': 1},
                'usb': {'configured': True, 'attached': True, 'join_relay': 'ready'},
                'purpose': 'development',
                'policy': {'zero_touch_open': False, 'decision_mode': 'lab_inventory',
                           'decision_timeout_ms': 1000, 'pending_retry_after_s': 30,
                           'policy_generation': 1, 'lab_enrollment_active': True},
                'clock': 'host_unix_ms', 'now_ms': unix}

    # --- fake RollcallService (D09 shape) ---

    def _rollcall(self, method, params, elapsed):
        if method == 'lab.rollcall.start':
            desired = params.get('desired_interval_ms', 2000)
            if type(desired) is not int or not 2000 <= desired <= 600_000:
                raise FakeMethodError('INVALID_ARGUMENT')
            if self.rollcall is not None:
                raise FakeMethodError('BUSY', True, retry_after_ms=1000)
            self.runs += 1
            self.rollcall = {'run_id': f'rc-{self.runs:04d}', 'started': elapsed, 'desired': desired}
            return {'run_id': self.rollcall['run_id'], 'state': 'running'}
        if method == 'lab.rollcall.update':
            desired = params.get('desired_interval_ms')
            if self.rollcall is None or type(desired) is not int or not 2000 <= desired <= 600_000:
                raise FakeMethodError('INVALID_ARGUMENT')
            self.rollcall['desired'] = desired
            return {'run_id': self.rollcall['run_id'], 'state': 'running'}
        if method == 'lab.rollcall.stop':
            self.rollcall = None
            return {'state': 'stopped'}
        return self._rollcall_status(elapsed)

    def _rollcall_status(self, elapsed):
        if self.rollcall is None:
            return {'state': 'stopped', 'counts': {}, 'statuses': []}
        parents, offline, departed = self.topology(elapsed)
        confirmed = [n for n in self.ids if self._confirmed(n, elapsed)]
        count = len(confirmed)
        floor = rollcall_interval_floor_ms(max(count, 1))
        effective = max(self.rollcall['desired'], -(-floor // 1000) * 1000)
        started = self.rollcall['started']
        polls = (elapsed - started) // effective + 1
        members = [n for n in confirmed if n != GATEWAY]
        reachable = [n for n in members if n in parents]
        statuses = []
        for node in members:
            confirm = self.power_ms(node) + CONFIRM_MS
            first_poll = max(started, started + -(-(confirm - started) // effective) * effective)
            if first_poll > elapsed:
                continue
            last_poll = started + (elapsed - started) // effective * effective
            statuses.append({
                'node': node, 'kid': self._kid(node),
                'first_status_received_ms': self._unix(first_poll + STATUS_DELAY_MS),
                'last_status_received_ms': self._unix(last_poll + STATUS_DELAY_MS)
                if node in parents else None,
                'milestones': {
                    'boot_at': {'at_unix_ms': self._unix(self.power_ms(node) + 50), 'estimated': True},
                    'join_started_at': {'at_unix_ms': self._unix(self.power_ms(node) + 80),
                                        'estimated': True},
                    'member_adopted_at': {'at_unix_ms': self._unix(confirm - 20), 'estimated': True},
                    'first_rollcall_rx_at': {'at_unix_ms': self._unix(first_poll + 20),
                                             'estimated': True}}})
        return {'state': 'waiting_members' if not members else 'running',
                'run_id': self.rollcall['run_id'], 'poll_seq': polls, 'roster_revision': count,
                'desired_interval_ms': self.rollcall['desired'], 'effective_interval_ms': effective,
                'extension_reason': 'airtime_budget' if effective > self.rollcall['desired'] else None,
                'settle_ms': 150 + 40 * len(members), 'airtime_estimate_us_per_s':
                    round(1.5 * (count - 1) * 15_296 * 1000 / effective) if count > 1 else 0,
                'airtime_observed_us_per_s': None, 'status_age_ms': (elapsed - started) % effective,
                'lease_remaining_ms': 30_000, 'skipped': 0,
                'counts': {'inventory_planned': len(self.ids) - 1, 'active_members': len(members),
                           'tree_explained': len(members), 'delivered': len(reachable),
                           'nonmember': 0, 'missing': len(members) - len(reachable),
                           'unaccounted': 0},
                'statuses': statuses}
