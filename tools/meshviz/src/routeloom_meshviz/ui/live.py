"""Live monitor: rollcall state, per-device join timeline and animated join/route changes.

All reads go out as tagged requests on the API thread; this view schedules
them with a timer and drops replies from an earlier connection. Evidence-free
milestones stay empty, never 0 or a guess.
"""
import math
import time

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QPen
from PySide6.QtWidgets import (QCheckBox, QGraphicsLineItem, QHBoxLayout, QHeaderView, QLabel, QPushButton, QSpinBox, QSplitter,
                               QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from .. import views
from ..live_monitor import (JOIN_STATES, MILESTONE_LABELS, MILESTONES, JoinTimeline, SitePoller,
                            read_status_text, rollcall_summary, route_switches, transitions)
from .topology import TopologyView

TICK_MS = 500
PULSE_NS = 1_500_000_000
COMMAND_TIMEOUT_MS = 10_000
ROLLCALL_METHODS = ('lab.rollcall.start', 'lab.rollcall.update', 'lab.rollcall.stop',
                    'lab.rollcall.status')
JOIN_COLORS = {'未参加': QColor('#fafafa'), '観測のみ': QColor('#e0e0e0'),
               '検証済申請': QColor('#fff176'), '承認': QColor('#ffb74d'),
               'Member': QColor('#64b5f6'), '到達可能': QColor('#4caf50'), '除外': QColor('#9e9e9e')}
# Text marks accompany colours so the state never depends on colour alone.
JOIN_MARKS = {'未参加': '○', '観測のみ': '?', '検証済申請': '申', '承認': '承', 'Member': 'M',
              '到達可能': '●', '除外': '×'}
COLUMNS = ['node', '現在状態'] + [MILESTONE_LABELS[name] for name in MILESTONES]


def _mono_ms():
    return time.monotonic_ns() // 1_000_000


def fmt_clock(evidence):
    """Host wall-clock of a milestone; '~' marks a clock-mapped (estimated) device time."""
    if evidence is None:
        return ''
    seconds, ms = divmod(evidence.at_unix_ms, 1000)
    text = time.strftime('%H:%M:%S', time.localtime(seconds)) + f'.{ms:03d}'
    return ('~' if evidence.estimated else '') + text


class LiveTopology(TopologyView):
    """The topology graph coloured by join state; transitions pulse, positions never move."""
    def __init__(self):
        super().__init__()
        self.table.hide()
        self.detail.hide()
        self.join_states = {}
        self.pulses = {}
        self.edge_pulses = {}
        self.relays = {}
        self.relay_items = {}
        box = QCheckBox('Join relay')
        box.setChecked(True)
        box.toggled.connect(self._relayer)
        self.layers['relay'] = box
        self.layout().itemAt(0).layout().insertWidget(4, box)

    def set_join(self, states, changed, switches, now_ns, relays=None):
        self.join_states = dict(states)
        self.relays = dict(relays or {})
        for node, _, _ in changed:
            self.pulses[node] = now_ns
        for node, _, hop in switches:
            self.edge_pulses[('route', hop, node)] = now_ns

    def animating(self, now_ns):
        for table in (self.pulses, self.edge_pulses):
            for key, start in list(table.items()):
                if now_ns - start > PULSE_NS:
                    del table[key]
        return bool(self.pulses or self.edge_pulses)

    def _sync_nodes(self, model):
        # Devices known only from the ledger/timeline are drawn too (未参加 etc.).
        for node in self.join_states:
            if node not in model.nodes:
                model.nodes[node] = {'id': node, 'label': views.short_id(node),
                                     'state': views.UNKNOWN, 'hops': None}
        super()._sync_nodes(model)
        now = time.monotonic_ns()
        for node, item in self.node_items.items():
            state = self.join_states.get(node, '観測のみ')
            item.setBrush(QBrush(JOIN_COLORS.get(state, JOIN_COLORS['観測のみ'])))
            start = self.pulses.get(node)
            if start is not None and now - start <= PULSE_NS:
                phase = (now - start) / PULSE_NS
                item.setPen(QPen(QColor('#e65100'), 2 + 4 * abs(math.sin(phase * math.pi * 3))))
            role = 'GW ' if node == model.gateway else ''
            item.label.setText(f'{role}{views.short_id(node)} {JOIN_MARKS.get(state, "?")}')

    def _sync_edges(self, model):
        super()._sync_edges(model)
        wanted = self.relays if self.layers['relay'].isChecked() else {}
        for node in list(self.relay_items):
            if wanted.get(node) != self.relay_items[node][1] or node not in self.node_items:
                self.scene.removeItem(self.relay_items.pop(node)[0])
        for node, proxy in wanted.items():
            if node in self.relay_items or node not in self.node_items or proxy not in self.node_items:
                continue
            line = QGraphicsLineItem()
            line.setZValue(0)
            line.setPen(QPen(QColor('#8e24aa'), 1, Qt.PenStyle.DashDotLine))
            self.scene.addItem(line)
            self.relay_items[node] = (line, proxy)
            self._set_line(line, node, proxy)

    def _node_moved(self, node_id):
        super()._node_moved(node_id)
        for node, (line, proxy) in self.relay_items.items():
            if node_id in (node, proxy):
                self._set_line(line, node, proxy)

    def _highlight(self, model):
        keys = super()._highlight(model)
        return keys | set(self.edge_pulses)


class LiveView(QWidget):
    send_request = Signal(str, str, dict)
    record = Signal(list)
    node_selected = Signal(str)

    def __init__(self):
        super().__init__()
        self.site_label = QLabel()
        self.link_label = QLabel()
        self.rollcall_label = QLabel()
        for label in (self.site_label, self.link_label, self.rollcall_label):
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.interval = QSpinBox()
        self.interval.setRange(2, 600)
        self.interval.setValue(2)
        self.interval.setSuffix(' s（希望間隔。実効は daemon が延長）')
        self.start_button = QPushButton('点呼開始')
        self.update_button = QPushButton('間隔を変更')
        self.stop_button = QPushButton('点呼停止')
        self.marker_button = QPushButton('選択機器に電源 ON marker')
        self.marker_button.setToolTip('人が電源を入れた時刻の記録。USB 接続や初観測から推測しない')
        self.start_button.clicked.connect(lambda: self._command('lab.rollcall.start'))
        self.update_button.clicked.connect(lambda: self._command('lab.rollcall.update'))
        self.stop_button.clicked.connect(lambda: self._command('lab.rollcall.stop'))
        self.marker_button.clicked.connect(self._mark_power)
        controls = QHBoxLayout()
        for widget in (self.interval, self.start_button, self.update_button, self.stop_button,
                       self.marker_button):
            controls.addWidget(widget)
        controls.addStretch()
        self.command_status = QLabel()
        self.command_status.setWordWrap(True)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.cellClicked.connect(self._row_clicked)
        self.graph = LiveTopology()
        self.graph.node_selected.connect(self.select)
        self.detail = QTextBrowser()
        legend = QLabel('状態: ' + '　'.join(f'{JOIN_MARKS[s]} {s}' for s in JOIN_STATES) +
                        '。空欄は個別の証拠が無い時刻（0 や推測で埋めない）。~ は機器時計からの換算値。')
        legend.setWordWrap(True)
        lower = QSplitter()
        lower.addWidget(self.graph)
        lower.addWidget(self.detail)
        lower.setSizes([700, 300])
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(lower)
        splitter.setSizes([300, 420])
        layout = QVBoxLayout(self)
        layout.addWidget(self.site_label)
        layout.addWidget(self.link_label)
        layout.addWidget(self.rollcall_label)
        layout.addLayout(controls)
        layout.addWidget(self.command_status)
        layout.addWidget(self.summary)
        layout.addWidget(legend)
        layout.addWidget(splitter, 1)
        self.poller = SitePoller('live')
        self.timeline = JoinTimeline()
        self.mode = 'LIVE'
        self.connection = None
        self.selected = None
        self.command = None
        self.command_counter = 0
        self.retry_at_ms = 0
        self.rollcall = None
        self.rollcall_at_ms = None
        self.recorded_poll = None
        self.site_status = None
        self.site_id = None
        self.snapshot = None
        self.last_states = {}
        self.last_hops = {}
        self.dirty = True
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(TICK_MS)
        self._refresh_labels()

    # --- source lifecycle ----------------------------------------------------

    def set_source(self, mode, status):
        """Connection change or loss clears capabilities, selection and pending commands."""
        self.mode = mode
        connection = status.get('connection') if status.get('connected') else None
        if mode != 'LIVE' or connection != self.connection:
            self.connection = connection if mode == 'LIVE' else None
            self.poller.reset(status.get('methods', {}) if self.connection is not None else None)
            self.timeline.begin_session(self.connection)
            self.command = None
            self.retry_at_ms = 0
            self.rollcall = None
            self.site_status = None
            self._select(None)
        else:
            self.poller.set_methods(status.get('methods', {}))
        self.dirty = True
        self._refresh_labels()

    def reset_timeline(self):
        """A different source (daemon, site or capture) never inherits another's rows."""
        self.timeline = JoinTimeline()
        self.site_id = None
        self.last_states = {}
        self.last_hops = {}
        self.recorded_poll = None
        self.dirty = True

    # --- polling ------------------------------------------------------------

    def _tick(self):
        now = _mono_ms()
        if self.mode == 'LIVE':
            for tag, method, params in self.poller.due(now):
                self.send_request.emit(tag, method, params)
            if self.command is not None and now - self.command[2] > COMMAND_TIMEOUT_MS:
                self.command_status.setText(f'{self.command[1]}: 応答なし（結果は不明）')
                self.command = None
        self._refresh_labels()

    def on_reply(self, tag, reply):
        now = _mono_ms()
        if self.command is not None and tag == self.command[0]:
            self._on_command_reply(reply, now)
            return
        if not self.poller.owns(tag):
            return
        accepted = self.poller.on_reply(tag, reply, now)
        if accepted is None:
            self._refresh_labels()
            return
        kind, result = accepted
        changed = []
        if kind == 'site':
            site_id = result.get('site_id')
            if self.site_id is not None and site_id != self.site_id:
                # Same socket, different site (daemon replaced): start a fresh table.
                self.reset_timeline()
            self.site_id = site_id
            self.site_status = result
        elif kind == 'requests':
            changed = self.timeline.on_requests(result.get('requests'))
        elif kind == 'members':
            changed = self.timeline.on_members(result.get('members'))
        elif kind == 'rollcall':
            self.rollcall = rollcall_summary(result)
            self.rollcall_at_ms = now
            changed = self.timeline.on_statuses(result.get('statuses'), time.monotonic_ns())
            seq = self.rollcall.get('poll_seq') if self.rollcall else None
            if seq is not None and seq != self.recorded_poll:
                self.recorded_poll = seq
                self.record.emit([{'kind': 'rollcall_status', 'source': 'meshlab-live',
                                   'payload': dict(self.rollcall)}])
        self._after_change(changed)

    def on_routes(self, observation):
        if self.mode != 'LIVE' or observation.get('connection') != self.connection:
            return
        self._after_change(self.timeline.on_routes(observation))

    def _after_change(self, changed):
        if changed:
            self.record.emit([{'kind': 'join_milestone', 'source': 'meshlab-live', 'payload': change}
                              for change in changed])
        self._animate()
        self.dirty = True
        self._refresh_labels()

    def _animate(self):
        states = self.timeline.states()
        hops = {node: row.next_hop for node, row in self.timeline.rows.items()}
        relays = {node: row.join_proxy for node, row in self.timeline.rows.items() if row.join_proxy}
        self.graph.set_join(states, transitions(self.last_states, states),
                            route_switches(self.last_hops, hops), time.monotonic_ns(), relays)
        self.last_states = states
        self.last_hops = hops

    # --- commands -----------------------------------------------------------

    def rollcall_supported(self):
        return self.mode == 'LIVE' and all(self.poller.supported(m) for m in ROLLCALL_METHODS)

    def _command(self, method):
        now = _mono_ms()
        if not self.rollcall_supported() or self.command is not None or now < self.retry_at_ms:
            return
        params = {} if method == 'lab.rollcall.stop' else {'desired_interval_ms': self.interval.value() * 1000}
        self.command_counter += 1
        tag = f'live-cmd-{self.poller.generation}-{self.command_counter}'
        self.command = (tag, method, now)
        self.command_status.setText(f'{method}: 送信中')
        self.send_request.emit(tag, method, params)
        self._refresh_labels()

    def _on_command_reply(self, reply, now):
        _, method, _ = self.command
        self.command = None
        if reply is None:
            self.command_status.setText(f'{method}: 応答なし（結果は不明）')
        elif reply.get('ok'):
            self.command_status.setText(f'{method}: 受付 {reply["result"].get("state", "")}')
            self.poller.next_at['rollcall'] = now
        else:
            error = reply.get('error') or {}
            detail = error.get('detail') if isinstance(error.get('detail'), dict) else {}
            retry = detail.get('retry_after_ms')
            if type(retry) is int and retry > 0:
                self.retry_at_ms = now + retry
            self.command_status.setText(
                f'{method}: 拒否 {error.get("code")}' +
                (f'（{retry / 1000:.1f} s 後まで再送しない）' if type(retry) is int and retry > 0 else ''))
        self._refresh_labels()

    def _mark_power(self):
        if self.mode != 'LIVE' or self.selected is None:
            return
        self._after_change(self.timeline.mark_power_on(self.selected, time.time_ns() // 1_000_000))

    # --- selection ------------------------------------------------------------

    def _row_clicked(self, row, _):
        item = self.table.item(row, 0)
        if item is not None:
            self.select(item.data(Qt.ItemDataRole.UserRole))

    def select(self, node):
        self._select(node)
        self.node_selected.emit(node)

    def _select(self, node):
        self.selected = node
        self.graph.selected = node
        self.dirty = True
        self._show_detail()
        self._refresh_labels()

    # --- rendering ------------------------------------------------------------

    def animating(self):
        return self.graph.animating(time.monotonic_ns())

    def update_snapshot(self, snapshot):
        self.snapshot = snapshot
        if snapshot.get('mode') == 'REPLAY':
            self._replay(snapshot.get('site_events', []))
        self.graph.update_snapshot(snapshot)
        if self.dirty:
            self.dirty = False
            self._render_table()
            self._show_detail()

    def _replay(self, events):
        """REPLAY rebuilds the timeline and rollcall only from recorded events."""
        timeline = JoinTimeline()
        rollcall = None
        for event in events:
            if event.get('kind') == 'join_milestone':
                timeline.apply_recorded(event.get('payload') or {})
            elif event.get('kind') == 'rollcall_status':
                rollcall = event.get('payload')
        self.timeline = timeline
        self.rollcall = rollcall
        self.rollcall_at_ms = None
        self._animate()
        self.dirty = True
        self._refresh_labels()

    def _render_table(self):
        rows = sorted(self.timeline.rows.values(), key=lambda r: r.node)
        self.table.setUpdatesEnabled(False)
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            state = row.state()
            texts = [views.short_id(row.node) + (f'（再 provision {row.identity_changes}）'
                                                 if row.identity_changes else ''),
                     f'{JOIN_MARKS[state]} {state}'] + [fmt_clock(row.fields.get(name))
                                                       for name in MILESTONES]
            for c, text in enumerate(texts):
                cell = self.table.item(r, c)
                if cell is None:
                    cell = QTableWidgetItem()
                    self.table.setItem(r, c, cell)
                if cell.text() != text:
                    cell.setText(text)
            self.table.item(r, 0).setData(Qt.ItemDataRole.UserRole, row.node)
        self.table.setUpdatesEnabled(True)

    def _show_detail(self):
        row = self.timeline.rows.get(self.selected) if self.selected else None
        if row is None:
            self.detail.setPlainText('機器を選択すると、各時刻の証拠（source・内容）を表示します。')
            return
        lines = [f'node {row.node}', f'kid {row.kid or "不明"}', f'状態 {row.state()}',
                 f'gateway 観測 next hop: {views.fmt(row.next_hop)}', '']
        for name in MILESTONES:
            evidence = row.fields.get(name)
            if evidence is None:
                lines.append(f'{MILESTONE_LABELS[name]}: 証拠なし（空欄）')
            else:
                lines.append(f'{MILESTONE_LABELS[name]}: {fmt_clock(evidence)}  source={evidence.source}'
                             f'  {evidence.detail}' + ('（推定）' if evidence.estimated else ''))
        lines.append(f'Join relay（申請の via.proxy、未認証の経路情報）: {views.fmt(row.join_proxy)}')
        lines.append('heap／session／epoch／bench 統計: 未取得（health API は D05、bench は D06）')
        lines.append('')
        lines.append('経路安定: 同じ有効 next hop を 3 連続 snapshot かつ 5 秒以上、その間に app 応答'
                     '（gateway observer の観測。網全体の収束ではない）')
        self.detail.setPlainText('\n'.join(lines))

    def _refresh_labels(self):
        live = self.mode == 'LIVE'
        status = self.site_status or {}
        profile = status.get('profile') if isinstance(status.get('profile'), dict) else {}
        site_note = read_status_text(self.poller, 'site') if live else None
        self.site_label.setText(
            f'<b>{self.mode}</b>　site {views.fmt(status.get("site_id"))}'
            f'（{views.fmt(profile.get("purpose"))}）　security {views.fmt(profile.get("security"))}'
            f'　routing {views.fmt(profile.get("routing"))}' +
            (f'　site.status: {site_note}' if site_note else ''))
        usb = status.get('usb') if isinstance(status.get('usb'), dict) else {}
        authority = status.get('authority') if isinstance(status.get('authority'), dict) else {}
        self.link_label.setText(
            f'USB attached {views.fmt(usb.get("attached"))}　join relay {views.fmt(usb.get("join_relay"))}'
            f'　authority channel {views.fmt(authority.get("attached"))}　members '
            f'{views.fmt(status.get("members"))}（未確認 {views.fmt(status.get("members_unconfirmed"))}）'
            f'　参加要求 {views.fmt(status.get("join_requests"))}'
            + ('　（timeline 上限で打切り）' if self.timeline.truncated else ''))
        rollcall = self.rollcall
        if live and not self.rollcall_supported():
            note = read_status_text(self.poller, 'rollcall') or '未対応'
            self.rollcall_label.setText(f'常時点呼: {note}（RollcallService は D09）')
            self.summary.setText('')
        elif rollcall is None:
            self.rollcall_label.setText('常時点呼: ' + ('未取得' if live else '記録なし'))
            self.summary.setText('')
        else:
            age = (f'{(_mono_ms() - self.rollcall_at_ms) / 1000:.1f} s 前に取得'
                   if live and self.rollcall_at_ms is not None else '記録値')
            reason = rollcall.get('extension_reason')
            self.rollcall_label.setText(
                f'常時点呼: {views.fmt(rollcall.get("state"))}　希望 '
                f'{views.fmt(rollcall.get("desired_interval_ms"), "ms")}／実効 '
                f'{views.fmt(rollcall.get("effective_interval_ms"), "ms")}'
                + (f'（延長理由 {reason}）' if reason else '') + f'　{age}')
            counts = rollcall.get('counts') or {}
            waiting = rollcall.get('state') == 'waiting_members'
            self.summary.setText(
                ('参加 member 0 台: 待機中（空の poll は送らない）\n' if waiting else '') +
                f'予定 {views.fmt(counts.get("inventory_planned"))}　member '
                f'{views.fmt(counts.get("active_members"))}　木で確認 {views.fmt(counts.get("tree_explained"))}'
                f'　delivered {views.fmt(counts.get("delivered"))}　nonmember {views.fmt(counts.get("nonmember"))}'
                f'　missing {views.fmt(counts.get("missing"))}　unaccounted {views.fmt(counts.get("unaccounted"))}'
                f'\npoll {views.fmt(rollcall.get("poll_seq"))}　settle {views.fmt(rollcall.get("settle_ms"), "ms")}'
                f'　airtime 推定 {views.fmt(rollcall.get("airtime_estimate_us_per_s"), "us/s")}／観測 '
                f'{views.fmt(rollcall.get("airtime_observed_us_per_s"), "us/s")}　STATUS age '
                f'{views.fmt(rollcall.get("status_age_ms"), "ms")}　skip {views.fmt(rollcall.get("skipped"))}'
                '\ndelivered は SDK の group 配送集約であり、各アプリの健全性の証明ではない')
        can_send = self.rollcall_supported() and self.command is None and _mono_ms() >= self.retry_at_ms
        running = rollcall is not None and rollcall.get('state') in ('running', 'waiting_members')
        self.start_button.setEnabled(can_send and not running)
        self.update_button.setEnabled(can_send and running)
        self.stop_button.setEnabled(can_send and running)
        self.marker_button.setEnabled(live and self.selected is not None)

    def shutdown(self):
        self.timer.stop()
        self.command = None
