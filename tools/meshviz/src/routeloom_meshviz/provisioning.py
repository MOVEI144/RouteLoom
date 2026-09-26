"""Qt-free development provision plan and step runner (design-devflow §4.2, §7.3).

The runner only orders the steps and keeps each board's resumable state. The
steps themselves belong to other components: BoardConfig/setup (D02), the
keygen/PoP/identity orchestration (D03a) and the lab inventory policy (D01).
`ContractBackend` is the interface those components plug into; until they
exist every such step reports 未対応 and the board never reaches Ready. A board
is Ready only after the field readback matched (NodeId, kid, config, digest);
a write or an `OK sealed` answer alone is not Ready.
"""
from dataclasses import dataclass, field

from .board_setup import normalize_node_id

GROUP_ADDRESS_BASE = 0xFFFF_FFFF_FFFF_0000
LAB_ROLES = ('bridge', 'bench')

# (step, label, owner): owner names the component whose contract implements it.
STEPS = (
    ('plan', '計画（site・board・role・NodeId 予約）', 'Mesh Lab'),
    ('preflight', '書込前の再検証（chip/MAC/flash/保護/署名）', 'D03a'),
    ('setup', '共通 setup 書込み・BoardConfig commit', 'D02'),
    ('status', 'identity 状態の読出し', 'D03a'),
    ('keygen', '機器内 keygen と PoP', 'D03a'),
    ('issue', 'DevCert・identity bundle の発行', 'D03a'),
    ('identity', 'identity commit と lock（OK sealed）', 'D03a'),
    ('field', 'field image（app 領域のみ）書込み', 'D02'),
    ('readback', 'read-only boot identity の照合', 'D02'),
    ('inventory', 'inventory へ provision 完了を commit', 'D01'),
    ('join', '通常 Join・自動承認・JoinConfirm', 'D01'),
)
STEP_NAMES = tuple(step for step, _, _ in STEPS)
STEP_LABELS = {step: label for step, label, _ in STEPS}
STEP_OWNERS = {step: owner for step, _, owner in STEPS}
# Identity states the status step may report; only 'none' starts a new keygen.
IDENTITY_STATES = ('none', 'locked', 'sealed', 'uncertain', 'quarantined')


@dataclass
class StepResult:
    state: str  # done | failed | unsupported | attention
    detail: str = ''
    data: dict = field(default_factory=dict)
    resume_from: str | None = None


@dataclass
class ProvisionJob:
    board: str  # port path today; a board UUID once D02 exposes one
    chip: str | None
    base_mac: str | None
    role: str
    node_id: str
    steps: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    resume_from: str | None = None
    readback: dict | None = None

    @property
    def ready(self):
        return self.steps.get('readback') == 'done' and self.readback is not None

    @property
    def joined(self):
        return self.steps.get('join') == 'done'

    def next_step(self):
        for step in STEP_NAMES:
            if self.steps.get(step) != 'done':
                return step
        return None


def valid_lab_node_id(text):
    """NodeId for a lab device: 64-bit, not the invalid id and not the group namespace."""
    node = normalize_node_id(text)
    if node is None or int(node, 16) >= GROUP_ADDRESS_BASE:
        return None
    return node


def plan_jobs(boards):
    """boards: dicts {board, chip, base_mac, role, node_id} → (jobs, {board: [reasons]})."""
    errors = {}
    jobs = []
    node_ids, macs = {}, {}
    for board in boards:
        name = board.get('board')
        reasons = errors.setdefault(name, [])
        node = valid_lab_node_id(board.get('node_id'))
        if node is None:
            reasons.append('NodeId は 1..16 桁の hex（0・全 1・group 名前空間を除く）')
        else:
            node_ids.setdefault(node, []).append(name)
        if board.get('role') not in LAB_ROLES:
            reasons.append('役割は bridge か bench')
        mac = board.get('base_mac')
        if not isinstance(mac, str) or not mac:
            # The port alone is not an individual: ROM identity is required.
            reasons.append('ROM 検査で MAC を確認していない')
        else:
            macs.setdefault(mac.lower(), []).append(name)
        jobs.append(ProvisionJob(name, board.get('chip'), mac, board.get('role'), node))
    for node, names in node_ids.items():
        if len(names) > 1:
            for name in names:
                errors[name].append(f'NodeId {node} が重複')
    for mac, names in macs.items():
        if len(names) > 1:
            for name in names:
                errors[name].append(f'同じ基板（MAC {mac}）が複数 port に見える')
    bridges = [job.board for job in jobs if job.role == 'bridge']
    if len(bridges) > 1:
        for name in bridges:
            errors[name].append('bridge は site ごとに 1 台')
    errors = {name: reasons for name, reasons in errors.items() if reasons}
    for job in jobs:
        job.steps['plan'] = 'failed' if job.board in errors else 'done'
        if job.board in errors:
            job.details['plan'] = '／'.join(errors[job.board])
    return jobs, errors


class ContractBackend:
    """Step interface for the provision components. Steps not yet on main are 未対応."""
    name = 'contract'
    implemented = frozenset()

    def run(self, step, job):
        owner = STEP_OWNERS[step]
        return StepResult('unsupported', f'{owner} 未実装のため 未対応（契約: design-devflow §4.2）')


class FakeProvisionBackend(ContractBackend):
    """Demo backend for the fake API1 source: follows the same contract, touches no device."""
    name = 'fake'
    implemented = frozenset(STEP_NAMES[1:-1])

    def __init__(self, identity_states=None):
        self.identity_states = dict(identity_states or {})
        self.issued = {}

    def run(self, step, job):
        if step == 'status':
            state = self.identity_states.get(job.board, 'none')
            return StepResult('done', f'identity={state}', {'identity': state})
        if step == 'keygen':
            return StepResult('done', 'PoP 受領（fake）', {'kid': f'{int(job.node_id, 16):064x}'})
        if step == 'identity':
            return StepResult('done', 'OK sealed（fake）')
        if step == 'readback':
            kid = job.details.get('kid')
            return StepResult('done', 'NodeId/kid 一致（fake）',
                              {'node_id': job.node_id, 'kid': kid})
        return StepResult('done', 'fake')


class ProvisionRunner:
    """Runs one board at a time up to the first step that is not done.

    A failed step is resumable from the step the backend names (a lost keygen
    restarts from keygen with a new challenge, never reusing the PoP). A
    non-'none' identity stops the board as needs-attention: sealed boards go
    to the dedicated reconfiguration flow, never auto-deprovisioned here.
    """
    def __init__(self, backend, jobs, *, should_cancel=None):
        self.backend = backend
        self.jobs = list(jobs)
        self.cancelled = False
        self.should_cancel = should_cancel

    def run_job(self, job):
        if job.steps.get('plan') != 'done':
            return job
        start = job.resume_from or job.next_step()
        if start is None:
            return job
        job.resume_from = None
        started = False
        for step in STEP_NAMES:
            if step == start:
                started = True
            if not started or step == 'plan':
                continue
            if self.cancelled or (self.should_cancel is not None and self.should_cancel()):
                job.details[step] = '中止：未着手'
                job.resume_from = step
                break
            if step == 'join':
                # Join completion comes from the authority ledger (observe_join).
                job.steps.setdefault('join', 'waiting')
                break
            result = self.backend.run(step, job)
            job.steps[step] = result.state
            job.details[step] = result.detail
            if step == 'keygen' and result.state == 'done':
                job.details['kid'] = result.data.get('kid')
            if step == 'status' and result.state == 'done':
                identity = result.data.get('identity')
                if identity != 'none':
                    job.steps[step] = 'attention'
                    job.details[step] = (f'identity={identity}: 初回 provision の対象外'
                                         '（自動 deprovision しない。専用の再設定手順へ）')
                    break
            if step == 'readback' and result.state == 'done':
                expected = (job.node_id, job.details.get('kid'))
                got = (result.data.get('node_id'), result.data.get('kid'))
                if got != expected:
                    job.steps[step] = 'failed'
                    job.details[step] = f'readback 不一致 {got} ≠ {expected}'
                    job.resume_from = 'readback'
                    break
                job.readback = dict(result.data)
            if job.steps[step] != 'done':
                job.resume_from = result.resume_from or step
                break
        return job

    def observe_join(self, states):
        """states: {node: join state}; Member evidence closes the join step."""
        for job in self.jobs:
            if job.steps.get('join') == 'waiting' and states.get(job.node_id) in ('Member', '到達可能'):
                job.steps['join'] = 'done'
                job.details['join'] = '台帳 member かつ JoinConfirm 観測'

    def cancel(self):
        self.cancelled = True


def job_status_text(job):
    if job.steps.get('plan') == 'failed':
        return '計画不可'
    if job.joined:
        return '参加済み'
    if job.ready:
        return 'Ready（readback 一致）'
    for step in STEP_NAMES:
        state = job.steps.get(step)
        if state == 'unsupported':
            return f'未対応（{STEP_LABELS[step]}）'
        if state in ('failed', 'attention'):
            suffix = f'、再開: {STEP_LABELS[job.resume_from]}' if job.resume_from else ''
            return ('要対応' if state == 'attention' else '失敗') + f'（{STEP_LABELS[step]}{suffix}）'
    step = job.next_step()
    return '未着手' if step == 'preflight' else f'途中（次: {STEP_LABELS.get(step, step)}）'


def inventory_rows(result):
    """lab.inventory.list (D01) → rows; None when the daemon does not serve it."""
    if not isinstance(result, dict) or not isinstance(result.get('devices'), list):
        return None
    rows = []
    for item in result['devices'][:1024]:
        if isinstance(item, dict):
            rows.append({key: item.get(key) for key in
                         ('node_id', 'kid', 'role', 'board', 'provision_state', 'site')})
    return rows


def auto_approval_text(policy, inventory_supported):
    """Auto approval state from site.status.policy; absent lab policy fields are 未対応."""
    if not isinstance(policy, dict):
        return '不明（site.status 未取得）'
    mode = policy.get('decision_mode')
    zero_touch = policy.get('zero_touch_open')
    base = f'decision_mode={mode if mode is not None else "不明"}、zero_touch_open=' + \
        ('不明' if zero_touch is None else 'はい' if zero_touch else 'いいえ')
    lab = policy.get('lab_inventory')
    if not inventory_supported or lab is None:
        return base + '／開発 inventory 自動承認: 未対応（D01 の lab_inventory policy が無い）'
    if not isinstance(lab, dict):
        return base + '／開発 inventory 自動承認: 不明'
    enabled = lab.get('enabled')
    expires = lab.get('expires_ms')
    return (base + '／開発 inventory 自動承認: ' +
            ('有効' if enabled is True else '無効' if enabled is False else '不明') +
            (f'（期限 {expires} ms）' if type(expires) is int else ''))
