"""Low-rate unicast send trial; the runner is paced by a GUI timer, I/O stays on the API thread."""
import time

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (QComboBox, QDoubleSpinBox, QFormLayout, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QPushButton, QSpinBox, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from .. import views
from ..trial import TrialPlan, TrialRunner, estimate, summarize, validate
from .quality import trial_stats_by_destination

TICK_MS = 250
COLUMNS = ['index', 'admission', 'dispatch_state', 'result', '受理まで', '完了まで']


def _mono_ms():
    return time.monotonic_ns() // 1_000_000


class TrialsView(QWidget):
    send_request = Signal(str, str, dict)
    record = Signal(list)

    def __init__(self):
        super().__init__()
        self.network = QLineEdit('0000000000000001')
        self.destination = QComboBox()
        self.destination.setEditable(True)
        self.count = QSpinBox()
        self.count.setRange(1, 64)
        self.count.setValue(4)
        self.interval = QDoubleSpinBox()
        self.interval.setRange(1, 3600)
        self.interval.setValue(30)
        self.interval.setSuffix(' s')
        self.payload = QSpinBox()
        self.payload.setRange(0, 128)
        self.payload.setValue(32)
        self.payload.setSuffix(' B')
        self.delivery = QComboBox()
        self.delivery.addItems(['RELIABLE', 'BEST_EFFORT'])
        self.ttl = QSpinBox()
        self.ttl.setRange(1, 30000)
        self.ttl.setValue(5000)
        self.ttl.setSuffix(' ms')
        form = QFormLayout()
        form.addRow('network', self.network)
        form.addRow('宛先 NodeId', self.destination)
        form.addRow('回数', self.count)
        form.addRow('間隔', self.interval)
        form.addRow('payload 長', self.payload)
        form.addRow('delivery', self.delivery)
        form.addRow('TTL', self.ttl)
        self.estimate = QLabel()
        self.estimate.setWordWrap(True)
        self.start_button = QPushButton('試験開始')
        self.stop_button = QPushButton('停止（新規送信を止め、受理済みは drain）')
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        buttons = QHBoxLayout()
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.estimate)
        layout.addLayout(buttons)
        layout.addWidget(self.status)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.summary)
        for widget in (self.count, self.payload, self.ttl):
            widget.valueChanged.connect(self._refresh_estimate)
        self.interval.valueChanged.connect(self._refresh_estimate)
        self.network.textChanged.connect(self._refresh_estimate)
        self.destination.editTextChanged.connect(self._refresh_estimate)
        self.runner = None
        self.recorded = {}
        self.mode = 'LIVE'
        self.supported = False
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self._refresh_estimate()

    def plan(self):
        return TrialPlan(self.network.text().strip().lower(), self.destination.currentText().strip().lower(),
                         self.count.value(), int(round(self.interval.value() * 1000)),
                         self.payload.value(), self.delivery.currentText(), self.ttl.value())

    def _refresh_estimate(self):
        plan = self.plan()
        errors = validate(plan)
        if errors:
            self.estimate.setText('開始不可: ' + '／'.join(errors))
        else:
            e = estimate(plan)
            self.estimate.setText(
                f'admission 消費 {e["admission_calls"]} 件（open_epoch 1 件を含む。上限 毎分 2 件・burst 16）'
                f'{"、burst 内" if e["within_burst"] else "、持続 rate で送信"}　所要見込み '
                f'{e["duration_ms"] / 1000:.0f} 秒（TTL と 30 秒の drain 猶予を含む）')
        self._update_buttons(errors)

    def _update_buttons(self, errors=None):
        errors = validate(self.plan()) if errors is None else errors
        running = self.runner is not None and not self.runner.finished
        self.start_button.setEnabled(self.mode == 'LIVE' and self.supported and not running and not errors)
        self.stop_button.setEnabled(running)

    def set_capabilities(self, mode, methods):
        """REPLAY never sends; a daemon without the send methods shows 未対応."""
        self.mode = mode
        needed = ('operations.open_epoch', 'messages.submit', 'operations.get')
        self.supported = mode == 'LIVE' and all(methods.get(m) for m in needed)
        if mode != 'LIVE':
            self.status.setText('REPLAY 中は送信できません（記録された試験結果を表示）')
        elif not self.supported:
            self.status.setText('接続先 API1 が messages.submit／operations.* を広告していないため 未対応')
        elif self.runner is None:
            self.status.setText('')
        self._update_buttons()

    def set_nodes(self, nodes):
        current = self.destination.currentText()
        items = [n for n in nodes]
        if [self.destination.itemText(i) for i in range(self.destination.count())] != items:
            self.destination.blockSignals(True)
            self.destination.clear()
            self.destination.addItems(items)
            self.destination.setEditText(current if current else (items[1] if len(items) > 1 else ''))
            self.destination.blockSignals(False)
            self._refresh_estimate()

    def start(self):
        if self.mode != 'LIVE' or not self.supported:
            return
        try:
            self.runner = TrialRunner(self.plan(), _mono_ms())
        except ValueError as exc:
            self.status.setText(f'開始不可: {exc}')
            return
        self.recorded = {}
        # The plan is recorded before anything is sent.
        self._record_run()
        self.timer.start(TICK_MS)
        self._tick()

    def stop(self):
        if self.runner is not None:
            self.runner.abort()
            self._tick()

    def on_reply(self, tag, reply):
        if self.runner is not None and tag in self.runner.outstanding:
            self.runner.on_reply(tag, reply, _mono_ms())
            self._after_change()

    def _tick(self):
        if self.runner is None:
            return
        for tag, method, params in self.runner.due(_mono_ms()):
            self.send_request.emit(tag, method, params)
        self._after_change()

    def _after_change(self):
        runner = self.runner
        changed = []
        for message in runner.messages:
            key = message['index']
            if self.recorded.get(key) != message:
                self.recorded[key] = dict(message)
                changed.append({'kind': 'trial_message', 'source': 'meshviz-trial',
                                'payload': dict(message)})
        if changed:
            self.record.emit(changed)
        self._show(runner.messages, runner.summary())
        self.status.setText(f'試験 {runner.run_id[:8]}: {runner.state}'
                            + (f'（停止理由: {runner.stop_reason}）' if runner.stop_reason else ''))
        if runner.finished:
            self.timer.stop()
            self._record_run()
        self._update_buttons()

    def _record_run(self):
        from dataclasses import asdict
        runner = self.runner
        self.record.emit([{'kind': 'trial_run', 'source': 'meshviz-trial',
                           'payload': {'run_id': runner.run_id, 'plan': asdict(runner.plan),
                                       'state': runner.state, 'stop_reason': runner.stop_reason}}])

    def _show(self, messages, summary):
        self.table.setRowCount(len(messages))
        for row, m in enumerate(messages):
            admitted = (m['admitted_ms'] - m['submit_ms']) if m['admitted_ms'] and m['submit_ms'] else None
            done = (m['terminal_ms'] - m['submit_ms']) if (m['terminal_ms'] and m['submit_ms'] and
                                                           m['result'] == 'END_SDK_RECEIVED') else None
            texts = [str(m['index']), views.fmt(m['admission'], none='—'),
                     views.fmt(m['dispatch_state'], none='—'), m['result'],
                     views.fmt(admitted, 'ms', none='—'), views.fmt(done, 'ms', none='—')]
            for column, text in enumerate(texts):
                cell = self.table.item(row, column)
                if cell is None:
                    self.table.setItem(row, column, QTableWidgetItem(text))
                elif cell.text() != text:
                    cell.setText(text)
        latency = summary['latency_ms']
        refused = '、'.join(f'{k} {v}' for k, v in summary['refused'].items()) or 'なし'
        self.summary.setText(
            f'予定 {summary["planned"]}／送信 {summary["submitted"]}／host 受理 {summary["admitted"]}／'
            f'SDK 受領 {summary["success"]}／未決着・不明 {summary["unknown"]}／受理拒否 {refused}\n'
            f'SDK 配送成功率 {views.fmt_rate(summary["success_rate_min"])}〜'
            f'{views.fmt_rate(summary["success_rate_max"])}（不明を含む範囲）　完了遅延 '
            f'p50 {views.fmt(latency["p50"], "ms")} p90 {views.fmt(latency["p90"], "ms")} '
            f'p95 {views.fmt(latency["p95"], "ms")} p99 {views.fmt(latency["p99"], "ms")}（n={latency["n"]}）'
            '\nSDK 受領は application 処理の証明ではない。ping RTT ではなく host が観測した完了時間。')

    def show_recorded(self, trial_events):
        """REPLAY: display the recorded ledger read-only."""
        if self.mode == 'LIVE':
            return
        _, messages = trial_stats_by_destination(trial_events)
        messages.sort(key=lambda m: (m['run_id'], m['index']))
        self._show(messages, summarize(messages))

    def shutdown(self):
        """Stop new sends; admitted operations cannot be recalled by closing the GUI."""
        if self.runner is not None and not self.runner.finished:
            self.runner.abort('接続終了（未決着は不明）', drain=False)
            self._after_change()
        self.timer.stop()
