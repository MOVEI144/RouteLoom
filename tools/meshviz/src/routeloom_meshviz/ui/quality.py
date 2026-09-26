"""Per-node quality table, RSSI time series and delivery outcome distribution."""
import pyqtgraph as pg
from PySide6.QtWidgets import (QHeaderView, QLabel, QSplitter, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)
from PySide6.QtCore import Qt

from .. import views
from ..trial import summarize

COLUMNS = [('label', 'node'), ('state', '接続状態'), ('rssi', 'RSSI→GW'), ('rssi_avg', 'RSSI 平均'),
           ('observed', '観測から'), ('freshness', '鮮度'), ('link_cost', 'link cost'),
           ('route_metric', 'route metric'), ('hops', 'hop'), ('success', 'SDK 配送成功率'),
           ('latency_p50', '完了遅延 p50'), ('heap', 'heap')]
MAX_SERIES = 8
COLORS = ['#1e88e5', '#e53935', '#43a047', '#fb8c00', '#8e24aa', '#00897b', '#6d4c41', '#3949ab']


def trial_stats_by_destination(trial_events):
    """Latest ledger entry per (run, index), summarized per destination."""
    latest = {}
    for event in trial_events:
        if event['kind'] == 'trial_message':
            body = event['payload']
            latest[(body['run_id'], body['index'])] = body
    grouped = {}
    for message in latest.values():
        grouped.setdefault(message['destination'], []).append(message)
    return {node: summarize(messages) for node, messages in grouped.items()}, list(latest.values())


class QualityView(QWidget):
    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([title for _, title in COLUMNS])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        self.table.itemSelectionChanged.connect(self._replot)
        self.plot = pg.PlotWidget(axisItems={'bottom': pg.DateAxisItem()})
        self.plot.setLabel('left', 'RSSI', units='dBm')
        self.plot.addLegend()
        self.plot.showGrid(x=True, y=True, alpha=0.3)
        self.outcomes = pg.PlotWidget()
        self.outcomes.setTitle('配送結果の分布（試験 ledger）')
        self.outcomes_label = QLabel()
        self.outcomes_label.setWordWrap(True)
        self.note = QLabel('RSSI は gateway 直結 neighbor のみ（多 hop 先は 不明）。heap／reset／MAC 再送は '
                           'health・telemetry API 未公開のため 未取得。値の横に観測時刻からの経過と鮮度を表示。')
        self.note.setWordWrap(True)
        charts = QSplitter()
        charts.addWidget(self.plot)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(self.outcomes, 1)
        right_layout.addWidget(self.outcomes_label)
        charts.addWidget(right)
        charts.setSizes([600, 320])
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(charts)
        layout = QVBoxLayout(self)
        layout.addWidget(self.note)
        layout.addWidget(splitter, 1)
        self.snapshot = None
        self.scope = None
        self.curves = {}

    def update_snapshot(self, snapshot):
        self.snapshot = snapshot
        state = snapshot['state']
        available = views.scopes(state)
        self.scope = available[0] if available else None
        stats, messages = trial_stats_by_destination(snapshot.get('trial_events', []))
        rows = views.quality_rows(state, self.scope, snapshot.get('now_unix_ms'), stats) if self.scope else []
        selected = self._selected_nodes()
        self.table.blockSignals(True)
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, (key, _) in enumerate(COLUMNS):
                cell = self.table.item(r, c)
                if cell is None:
                    cell = QTableWidgetItem()
                    self.table.setItem(r, c, cell)
                if cell.text() != row[key]:
                    cell.setText(row[key])
            self.table.item(r, 0).setData(Qt.ItemDataRole.UserRole, row['node'])
        self.table.blockSignals(False)
        self._update_outcomes(messages)
        self._replot(selected)

    def _selected_nodes(self):
        return [self.table.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
                for index in self.table.selectionModel().selectedRows()
                if self.table.item(index.row(), 0) is not None]

    def _replot(self, selected=None):
        if self.snapshot is None or self.scope is None:
            return
        selected = selected if selected is not None else self._selected_nodes()
        history = self.snapshot.get('history', {})
        prefix = f'{self.scope}:rssi_dbm/'
        keys = sorted(k for k in history if k.startswith(prefix))
        if selected:
            keys = [k for k in keys if k[len(prefix):].split('/')[0] in selected]
        # Draw at most eight series; raw samples stay in the capture.
        keys = keys[:MAX_SERIES]
        for key in list(self.curves):
            if key not in keys:
                self.plot.removeItem(self.curves.pop(key))
        for i, key in enumerate(keys):
            points = [(t / 1000, float('nan') if v is None else v) for t, v in history[key]]
            curve = self.curves.get(key)
            if curve is None:
                origin, _, observer = key[len(prefix):].partition('/')
                name = f'{views.short_id(origin)}→{views.short_id(observer)}'
                curve = self.plot.plot(name=name, pen=pg.mkPen(COLORS[i % len(COLORS)], width=1.5),
                                       symbol='o', symbolSize=3)
                self.curves[key] = curve
            # Unknown samples are gaps (connect='finite'), never plotted as 0.
            xs = [x for x, _ in points]
            ys = [y for _, y in points]
            curve.setData(xs, ys, connect='finite')

    def _update_outcomes(self, messages):
        summary = summarize(messages)
        self.outcomes.clear()
        names = sorted(summary['outcomes'])
        if names:
            bars = pg.BarGraphItem(x=list(range(len(names))), height=[summary['outcomes'][n] for n in names],
                                   width=0.6, brush='#1e88e5')
            self.outcomes.addItem(bars)
            self.outcomes.getAxis('bottom').setTicks([list(enumerate(names))])
        latency = summary['latency_ms']
        self.outcomes_label.setText(
            f'送信 {summary["submitted"]}／受理 {summary["admitted"]}／SDK 受領 {summary["success"]}／'
            f'未決着・不明 {summary["unknown"]}　成功率 {views.fmt_rate(summary["success_rate_min"])}〜'
            f'{views.fmt_rate(summary["success_rate_max"])}　遅延 p50 {views.fmt(latency["p50"], "ms")} '
            f'p95 {views.fmt(latency["p95"], "ms")}（n={latency["n"]}）' if messages else
            '試験結果なし（配送理由の詳細分布は HostOps 拡張後）')
