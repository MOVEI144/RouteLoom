"""Boards screen: enumerate, ROM-probe on request, assign, preview and run guarded writes."""
from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from ..board_setup import ROLES, BoardRow, assignment_errors, preview
from .workers import BoardWorker

COLUMNS = ['port', 'USB', 'chip', 'MAC 末尾', 'flash', '役割', 'NodeId', '状態']


def _flash_text(identity):
    if identity is None:
        return '不明'
    return f'{identity.flash_bytes >> 20} MB' if identity.flash_bytes else '不明'


class BoardsView(QWidget):
    probe_requested = Signal(list)
    flash_requested = Signal(list)
    scan_requested = Signal()
    bundle_requested = Signal(int, str)
    stop_requested = Signal()
    shutdown_finished = Signal()

    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.rows = []
        self.manifest = None
        self.bundle = None
        self.image_node_id = None
        self._bundle_serial = 0
        self.mode = 'LIVE'
        self.busy = False
        self.stopped = False
        self.stopping = False
        self.bundle_label = QLabel('bundle: 未選択')
        self.bundle_label.setWordWrap(True)
        choose = QPushButton('bundle を選択…')
        choose.clicked.connect(self._choose_bundle)
        rescan = QPushButton('port を再列挙')
        rescan.clicked.connect(self.rescan)
        self.probe_button = QPushButton('選択台を ROM 検査')
        self.probe_button.setToolTip('ROM probe は board を reset する。観測・送信中の board には使わない')
        self.probe_button.clicked.connect(self._probe_selected)
        self.quiesce = QCheckBox('選択 port を使う daemon／console／log を停止した（quiesce）')
        self.quiesce.toggled.connect(self._refresh_preview)
        self.flash_button = QPushButton('選択台を書込み')
        self.flash_button.clicked.connect(self._flash_selected)
        self.cancel_button = QPushButton('次の台から中止')
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        top = QHBoxLayout()
        for widget in (rescan, self.probe_button, choose, self.flash_button, self.cancel_button):
            top.addWidget(widget)
        top.addStretch()
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(2000)
        splitter = QSplitter()
        splitter.addWidget(self.table)
        splitter.addWidget(self.preview)
        splitter.setSizes([640, 420])
        note = QLabel('手順: 接続 → ROM 検査 → 役割・NodeId 割当て → bundle → 書込み。'
                      '書込み成功と起動・mesh 参加は別の状態（起動確認は PR 03a 以降）。')
        note.setWordWrap(True)
        layout = QVBoxLayout(self)
        layout.addWidget(note)
        layout.addLayout(top)
        layout.addWidget(self.bundle_label)
        layout.addWidget(self.quiesce)
        layout.addWidget(splitter, 1)
        layout.addWidget(QLabel('結果'))
        layout.addWidget(self.log)
        self.thread = QThread(self)
        self.worker = BoardWorker(backend)
        self.worker.moveToThread(self.thread)
        self.probe_requested.connect(self.worker.probe)
        self.flash_requested.connect(self.worker.flash)
        self.scan_requested.connect(self.worker.scan)
        self.bundle_requested.connect(self.worker.load_bundle)
        self.worker.progress.connect(self._on_progress)
        self.worker.probed.connect(self._on_probed)
        self.worker.finished.connect(self._on_finished)
        self.worker.scanned.connect(self._on_scanned)
        self.worker.bundle_loaded.connect(self._on_bundle_loaded)
        self.stop_requested.connect(self.worker.stop)
        self.worker.stopped.connect(self.thread.quit)
        self.thread.finished.connect(self._on_shutdown_finished)
        self.thread.start()
        self.rescan()

    # --- inventory ----------------------------------------------------------

    def rescan(self):
        if self.stopping:
            return
        self.quiesce.setChecked(False)
        self.scan_requested.emit()

    def _selection_changed(self):
        self.quiesce.setChecked(False)
        self._refresh_preview()

    def _on_scanned(self, ports, error):
        if error:
            self.log.appendPlainText(f'port 列挙に失敗: {error}')
        known = {row.port: row for row in self.rows}
        rows = []
        for port in ports:
            row = known.get(port.path) or BoardRow(port.path)
            vidpid = f'{port.vid:04x}:{port.pid:04x}' if port.vid is not None and port.pid is not None else '?'
            usb = f'{vidpid} {port.serial or "serial なし"} @{port.location or "?"}'
            if row.usb and row.usb != usb:
                # A port path is not an identity: a different device there needs a new probe.
                row.identity, row.state, row.message = None, 'Enumerated', 'ROM 再検査が必要'
            row.usb = usb
            rows.append(row)
        self.rows = rows
        self._render()

    def _render(self):
        errors = assignment_errors(self.rows)
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.rows))
        for r, row in enumerate(self.rows):
            identity = row.identity
            texts = [row.port, row.usb, identity.chip if identity else '不明',
                     '..' + identity.base_mac[-5:] if identity else '不明', _flash_text(identity)]
            for c, text in enumerate(texts):
                self.table.setItem(r, c, QTableWidgetItem(text))
            role = self.table.cellWidget(r, 5)
            if role is None:
                role = QComboBox()
                role.addItems(['（未割当て）', *ROLES])
                role.currentIndexChanged.connect(lambda i, rr=r: self._set_role(rr, i))
                self.table.setCellWidget(r, 5, role)
            role.blockSignals(True)
            role.setCurrentIndex(0 if row.role is None else 1 + ROLES.index(row.role))
            role.blockSignals(False)
            node = self.table.cellWidget(r, 6)
            if node is None:
                node = QLineEdit()
                node.setPlaceholderText('hex')
                node.editingFinished.connect(lambda rr=r: self._set_node(rr))
                self.table.setCellWidget(r, 6, node)
            if node.text() != (row.node_id or ''):
                node.setText(row.node_id or '')
            problems = errors[row.port]
            state = row.state + (' ⚠ ' + '；'.join(problems) if problems else '')
            item = QTableWidgetItem(state + (f' — {row.message}' if row.message else ''))
            self.table.setItem(r, 7, item)
        self.table.blockSignals(False)
        self._refresh_preview()

    def _set_role(self, r, index):
        if r < len(self.rows):
            self.rows[r].role = None if index == 0 else ROLES[index - 1]
            self._render()

    def _set_node(self, r):
        if r < len(self.rows):
            text = self.table.cellWidget(r, 6).text().strip()
            self.rows[r].node_id = text or None
            self._render()

    def set_assignment(self, port, role, node_id):
        """Programmatic assignment (tests and rig import use the same checks)."""
        for row in self.rows:
            if row.port == port:
                row.role, row.node_id = role, node_id
        self._render()

    def select_ports(self, ports):
        self.table.clearSelection()
        mode = self.table.selectionMode()
        self.table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        for r, row in enumerate(self.rows):
            if row.port in ports:
                self.table.selectRow(r)
        self.table.setSelectionMode(mode)

    def _selected(self):
        indices = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        return [self.rows[i] for i in indices if i < len(self.rows)]

    # --- bundle and preview ---------------------------------------------------

    def _choose_bundle(self):
        path = QFileDialog.getExistingDirectory(self, '署名付き firmware bundle')
        if path:
            self.load_bundle(path)

    def load_bundle(self, path):
        if self.stopping:
            return
        self.manifest = self.bundle = self.image_node_id = None
        self.bundle_label.setText(f'bundle 検証中: {path}')
        self._refresh_preview()
        self._bundle_serial += 1
        self._bundle_pending = self._bundle_serial
        self.bundle_requested.emit(self._bundle_serial, path)

    def _on_bundle_loaded(self, serial, path, manifest, image_node_id, error):
        if serial != self._bundle_pending:
            return
        if error:
            self.manifest = self.bundle = self.image_node_id = None
            self.bundle_label.setText(f'bundle 拒否: {error}')
        else:
            self.manifest = manifest
            self.bundle = path
            self.image_node_id = image_node_id
            self.bundle_label.setText(f'bundle: {path}\n  {manifest["chip"]} {manifest["role"]} '
                                      f'{manifest["firmware_version"]} — 署名・hash 検証済み（開発鍵）'
                                      f'／resolved Kconfig NodeId {image_node_id or "不明"}')
        self._refresh_preview()

    def plans(self):
        errors = assignment_errors(self.rows)
        return [(row, *preview(row, self.manifest, self.bundle, quiesced=self.quiesce.isChecked(),
                               assignment_problems=errors[row.port], image_node_id=self.image_node_id))
                for row in self._selected()]

    def _refresh_preview(self):
        lines = []
        plans = self.plans()
        for row, plan, reasons, notes in plans:
            lines.append(f'■ {row.port}: {"書込み可" if plan else "書込み不可"}')
            lines.extend(f'  ✗ {reason}' for reason in reasons)
            lines.extend(f'  {note}' for note in notes)
        if not plans:
            lines.append('board を選択すると書込み計画を表示します。')
        self.preview.setPlainText('\n'.join(lines))
        writable = [p for p in plans if p[1] is not None]
        self.flash_button.setEnabled(self.mode == 'LIVE' and not self.busy and bool(plans) and
                                     len(writable) == len(plans))
        self.probe_button.setEnabled(self.mode == 'LIVE' and not self.busy and bool(plans) and
                                     self.quiesce.isChecked())

    def set_mode(self, mode):
        """REPLAY never writes or probes boards."""
        self.mode = mode
        if mode != 'LIVE':
            self.quiesce.setChecked(False)
        self._refresh_preview()

    # --- actions ------------------------------------------------------------

    def _probe_selected(self):
        if self.stopping:
            return
        ports = [row.port for row in self._selected()]
        if ports and self.mode == 'LIVE' and self.quiesce.isChecked():
            self.busy = True
            self.worker.cancel.clear()
            self._refresh_preview()
            self.probe_requested.emit(ports)

    def _flash_selected(self):
        if self.stopping:
            return
        plans = self.plans()
        if self.mode != 'LIVE' or not plans or any(plan is None for _, plan, _, _ in plans):
            return
        self.busy = True
        self.worker.cancel.clear()
        self.cancel_button.setEnabled(True)
        for row, _, _, _ in plans:
            row.state, row.message = 'Preflight', '待機'
        self._render()
        # Writes are serial; each board is rechecked by the worker in its own ROM session.
        self.flash_requested.emit([(row.port, plan) for row, plan, _, _ in plans])

    def _cancel(self):
        self.worker.cancel.set()
        self.log.appendPlainText('中止要求: 書込み中の台は安全な終了点まで続け、待機台は開始しない')

    def _row(self, port):
        return next((row for row in self.rows if row.port == port), None)

    def _on_progress(self, port, state, message):
        row = self._row(port)
        if row:
            row.state, row.message = state, message
            self._render()

    def _on_probed(self, port, identity, error):
        row = self._row(port)
        if row is None:
            return
        if identity is None:
            row.identity, row.state, row.message = None, 'Failed', error
            self.log.appendPlainText(f'{port}: ROM 検査失敗: {error}')
        else:
            row.identity, row.state, row.message = identity, 'Identified', ''
            protection = ('保護状態 確認済み（無効）' if identity.secure_boot is False and
                          identity.flash_encryption is False else '保護状態 不明または有効 → 書込み拒否')
            self.log.appendPlainText(f'{port}: {identity.chip} rev{identity.revision} MAC {identity.base_mac} '
                                     f'flash {_flash_text(identity)}、{protection}')
        self._render()

    def _on_finished(self, results):
        self.busy = False
        self.cancel_button.setEnabled(False)
        for port, ok, error in results:
            row = self._row(port)
            if row:
                # ROM write+verify only; boot and site participation are separate, later states.
                row.state = 'Written' if ok else 'Failed'
                row.message = '書込み・verify 完了（起動確認は未対応）' if ok else (error or '')
            self.log.appendPlainText(f'{port}: {"成功" if ok else "失敗"} {error or ""}')
        self._render()

    def shutdown(self):
        if self.stopping:
            return
        self.stopping = True
        self.set_mode('REPLAY')
        self.worker.cancel.set()
        self.stop_requested.emit()

    def _on_shutdown_finished(self):
        self.stopped = True
        self.shutdown_finished.emit()
