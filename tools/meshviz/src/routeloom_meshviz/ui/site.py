"""Development site / provision wizard: site create or attach, board plan, provision, inventory.

The order follows design-devflow §7.3: site → board/role → provision →
readback → bridge join → live monitor. The daemon supervisor and the
provision steps run on worker threads; this screen only holds copies of their
results. Steps whose components are not on main (D01/D02/D03a) show 未対応.
"""
from copy import deepcopy
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .. import views
from ..live_monitor import read_status_text
from ..site_supervisor import SiteSupervisor
from ..provisioning import (LAB_ROLES, STEP_NAMES, ContractBackend, FakeProvisionBackend,
                            ProvisionRunner, auto_approval_text, inventory_rows, job_status_text,
                            plan_jobs, valid_lab_node_id)
from .workers import ProvisionWorker, SupervisorWorker

BOARD_COLUMNS = ['board（port）', 'chip', 'MAC 末尾', '役割', 'NodeId', 'provision 状態', '手順']
INVENTORY_COLUMNS = ['NodeId', 'kid', '役割', 'board', 'provision', 'site']
STEP_MARKS = {'done': '✓', 'failed': '✗', 'unsupported': '−', 'attention': '!', 'waiting': '…'}


class SiteView(QWidget):
    start_site = Signal(dict)
    attach_site = Signal(dict)
    stop_site = Signal()
    lab_init = Signal(int, str, str, int)  # serial, gateway NodeId, out dir, channel
    provision = Signal(int, object)
    provision_stop = Signal()
    site_ready = Signal(str)
    stop_requested = Signal()
    shutdown_finished = Signal()

    def __init__(self, boards_view, *, fake=False, supervisor=None):
        super().__init__()
        self.boards_view = boards_view
        self.fake = fake
        self.mode = 'LIVE'
        self.connection = None
        self.stopped = False
        self.stopping = False
        self.supervisor_status = {}
        self.ready_session = None
        self.lab_serial = 0
        self.provision_serial = 0
        self.jobs = []
        self.board_rows = []
        # --- 1. site --------------------------------------------------------
        self.gateway_id = QLineEdit()
        self.gateway_id.setPlaceholderText('bridge（gateway）の NodeId')
        self.channel = QSpinBox()
        self.channel.setRange(1, 14)
        self.channel.setValue(1)
        self.new_dir = QLineEdit()
        self.new_dir.setPlaceholderText('新規 site の出力 directory（空であること）')
        create = QPushButton('新規開発 site を作成（lab-site-init）')
        create.clicked.connect(self._create_site)
        self.site_dir = QLineEdit()
        self.site_dir.setPlaceholderText('site directory（site-authority.json・sak.key・site.db）')
        pick = QPushButton('…')
        pick.clicked.connect(self._pick_site)
        self.socket_path = QLineEdit()
        self.socket_path.setPlaceholderText('API socket（空なら site/ipc/api1.sock）')
        self.daemon_path = QLineEdit('routeloom-host')
        self.device = QLineEdit()
        self.device.setPlaceholderText('bridge の serial port（任意）')
        self.acl_file = QLineEdit()
        self.acl_file.setPlaceholderText('API ACL file（任意）')
        self.expected_site = QLineEdit()
        self.expected_site.setPlaceholderText('期待する site_id（16 hex、任意。初回接続で固定）')
        self.start_button = QPushButton('daemon を起動（Mesh Lab 所有）')
        self.attach_button = QPushButton('既存 daemon に attach')
        self.stop_button = QPushButton('停止／attach 解除')
        self.start_button.clicked.connect(lambda: self._site_command(self.start_site))
        self.attach_button.clicked.connect(lambda: self._site_command(self.attach_site))
        self.stop_button.clicked.connect(self.stop_site.emit)
        new_form = QFormLayout()
        new_form.addRow('gateway', self.gateway_id)
        new_form.addRow('channel', self.channel)
        new_form.addRow('出力先', self.new_dir)
        new_form.addRow(create)
        new_box = QGroupBox('新規開発 site')
        new_box.setLayout(new_form)
        site_row = QHBoxLayout()
        site_row.addWidget(self.site_dir, 1)
        site_row.addWidget(pick)
        attach_form = QFormLayout()
        attach_form.addRow('site directory', site_row)
        attach_form.addRow('socket', self.socket_path)
        attach_form.addRow('daemon', self.daemon_path)
        attach_form.addRow('bridge port', self.device)
        attach_form.addRow('ACL', self.acl_file)
        attach_form.addRow('site_id', self.expected_site)
        buttons = QHBoxLayout()
        for widget in (self.start_button, self.attach_button, self.stop_button):
            buttons.addWidget(widget)
        attach_form.addRow(buttons)
        attach_box = QGroupBox('既存 site へ接続（daemon の起動・監視・再接続）')
        attach_box.setLayout(attach_form)
        self.supervisor_label = QLabel()
        self.supervisor_label.setWordWrap(True)
        self.lab_label = QLabel()
        self.lab_label.setWordWrap(True)
        # --- 2/3. boards and provision -------------------------------------------
        import_button = QPushButton('ボード画面の検査結果を取込')
        import_button.clicked.connect(self.import_boards)
        self.plan_button = QPushButton('計画を検証')
        self.plan_button.clicked.connect(self.validate_plan)
        self.confirm = QCheckBox('対象 port を daemon／console から外し、provision（reset・書込み）を実行してよい')
        self.confirm.toggled.connect(self._refresh_buttons)
        self.run_button = QPushButton('provision 実行')
        self.run_button.clicked.connect(self.run_provision)
        self.cancel_button = QPushButton('次の台から中止')
        self.cancel_button.clicked.connect(self._cancel)
        board_buttons = QHBoxLayout()
        for widget in (import_button, self.plan_button, self.run_button, self.cancel_button):
            board_buttons.addWidget(widget)
        board_buttons.addStretch()
        self.board_table = QTableWidget(0, len(BOARD_COLUMNS))
        self.board_table.setHorizontalHeaderLabels(BOARD_COLUMNS)
        self.board_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.board_table.verticalHeader().setVisible(False)
        self.plan_label = QLabel()
        self.plan_label.setWordWrap(True)
        self.backend_label = QLabel()
        self.backend_label.setWordWrap(True)
        # --- 4. inventory / auto approval ------------------------------------------
        self.approval_label = QLabel()
        self.approval_label.setWordWrap(True)
        self.inventory_table = QTableWidget(0, len(INVENTORY_COLUMNS))
        self.inventory_table.setHorizontalHeaderLabels(INVENTORY_COLUMNS)
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.inventory_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.inventory_label = QLabel()
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(new_box)
        top.addWidget(attach_box, 1)
        layout.addLayout(top)
        layout.addWidget(self.lab_label)
        layout.addWidget(self.supervisor_label)
        layout.addWidget(QLabel('<b>ボード → 個体設定 → provision → readback → 参加</b>'))
        layout.addWidget(self.backend_label)
        layout.addLayout(board_buttons)
        layout.addWidget(self.confirm)
        layout.addWidget(self.board_table, 1)
        layout.addWidget(self.plan_label)
        layout.addWidget(QLabel('<b>inventory と自動承認</b>'))
        layout.addWidget(self.approval_label)
        layout.addWidget(self.inventory_label)
        layout.addWidget(self.inventory_table, 1)
        layout.addWidget(self.log)
        # --- workers ------------------------------------------------------------
        backend = FakeProvisionBackend() if fake else ContractBackend()
        self.backend_label.setText(
            'provision backend: ' + ('fake（demo。機器に触れない）' if fake else
                                     'D02／D03a の契約 interface（未実装の手順は 未対応。Ready にならない）'))
        self.sup_thread = QThread(self)
        # The bridge port is fenced by the same leases as ROM probes and writes.
        self.sup_worker = SupervisorWorker(supervisor or SiteSupervisor(leases=boards_view.backend.leases))
        self.sup_worker.moveToThread(self.sup_thread)
        self.sup_thread.started.connect(self.sup_worker.start)
        self.start_site.connect(self.sup_worker.start_site)
        self.attach_site.connect(self.sup_worker.attach_site)
        self.stop_site.connect(self.sup_worker.stop_site)
        self.lab_init.connect(self.sup_worker.lab_init)
        self.sup_worker.status.connect(self._on_supervisor)
        self.sup_worker.lab_init_done.connect(self._on_lab_init)
        self.stop_requested.connect(self.sup_worker.stop)
        self.sup_worker.stopped.connect(self.sup_thread.quit)
        self.prov_thread = QThread(self)
        self.prov_worker = ProvisionWorker(backend)
        self.prov_worker.moveToThread(self.prov_thread)
        self.provision.connect(self.prov_worker.run)
        self.prov_worker.job_updated.connect(self._on_job)
        self.prov_worker.finished.connect(self._on_provision_finished)
        self.provision_stop.connect(self.prov_worker.stop)
        self.prov_worker.stopped.connect(self.prov_thread.quit)
        self.sup_thread.finished.connect(self._on_thread_finished)
        self.prov_thread.finished.connect(self._on_thread_finished)
        self.threads_running = 2
        self.sup_thread.start()
        self.prov_thread.start()
        self.provisioning = False
        self._render_boards()
        self._refresh_buttons()

    # --- source ---------------------------------------------------------------

    def set_source(self, mode, status):
        """A new connection or REPLAY clears the operator's confirmation."""
        connection = status.get('connection') if status.get('connected') else None
        if mode != self.mode or connection != self.connection:
            self.confirm.setChecked(False)
        self.mode = mode
        self.connection = connection
        self._refresh_buttons()

    def update_from(self, live):
        """Inventory and approval come from the live poller's reads (no duplicate requests)."""
        status = live.site_status or {}
        site_note = read_status_text(live.poller, 'site') if self.mode == 'LIVE' else None
        if live.site_status is None and site_note is not None:
            self.approval_label.setText(f'自動承認: site.status {site_note}')
        else:
            self.approval_label.setText('自動承認: ' + auto_approval_text(status))
        result = live.poller.results.get('inventory')
        rows = inventory_rows(result[0]) if result else None
        note = read_status_text(live.poller, 'inventory') if self.mode == 'LIVE' else '再生中は照会しない'
        self.inventory_label.setText('inventory: ' + (note or f'{len(rows or [])} 台'))
        rows = rows or []
        self.inventory_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            texts = [views.short_id(row['node_id']), (row['kid'] or '不明')[:12], views.fmt(row['role']),
                     views.fmt(row['board']), views.fmt(row['provision_state']), views.fmt(row['site'])]
            for c, text in enumerate(texts):
                cell = self.inventory_table.item(r, c)
                if cell is None:
                    self.inventory_table.setItem(r, c, QTableWidgetItem(text))
                elif cell.text() != text:
                    cell.setText(text)
        if self.jobs:
            ProvisionRunner(None, self.jobs).observe_join(live.timeline.states())
            self._render_boards()

    # --- site ------------------------------------------------------------------

    def _pick_site(self):
        path = QFileDialog.getExistingDirectory(self, 'site directory')
        if path:
            self.site_dir.setText(path)

    def site_config(self):
        site_dir = self.site_dir.text().strip()
        if not site_dir:
            return None
        socket = self.socket_path.text().strip() or str(Path(site_dir) / 'ipc' / 'api1.sock')
        expected = self.expected_site.text().strip().lower() or None
        return {'site_dir': Path(site_dir), 'socket': Path(socket),
                'daemon': self.daemon_path.text().strip() or 'routeloom-host',
                'device': self.device.text().strip() or None,
                'acl_file': Path(self.acl_file.text().strip()) if self.acl_file.text().strip() else None,
                'expected_site_id': expected}

    def _site_command(self, signal):
        config = self.site_config()
        if config is None:
            self.supervisor_label.setText('site directory を指定してください')
            return
        if config['expected_site_id'] is not None and (
                len(config['expected_site_id']) != 16 or
                any(c not in '0123456789abcdef' for c in config['expected_site_id'])):
            self.supervisor_label.setText('site_id は 16 桁の hex')
            return
        self.ready_session = None
        signal.emit(config)

    def _create_site(self):
        out = self.new_dir.text().strip()
        gateway = valid_lab_node_id(self.gateway_id.text())
        if not out or gateway is None:
            self.lab_label.setText('出力先と bridge の NodeId を指定してください')
            return
        self.lab_serial += 1
        # ids come from the CSPRNG into <out>.lab-spec.json; a retry reuses that spec
        # so lab-site-init resumes the same site rather than minting new CAs.
        self.lab_label.setText('lab-site-init 実行中…')
        self.lab_init.emit(self.lab_serial, gateway, out, self.channel.value())

    def _on_lab_init(self, serial, result):
        if serial != self.lab_serial:
            return  # an older request's answer
        state = result.get('state')
        text = {'created': '作成済み（daemon 起動へ）', 'unsupported': '未対応',
                'failed': '失敗'}.get(state, '不明')
        self.lab_label.setText(f'新規開発 site: {text}　{result.get("detail", "")[-300:]}')
        if state == 'created':
            self.site_dir.setText(self.new_dir.text().strip())
            self.acl_file.setText(result.get('acl_file', ''))

    def _on_supervisor(self, status):
        self.supervisor_status = status
        state = status.get('state')
        usb = status.get('usb') or {}
        authority = status.get('authority') or {}
        self.supervisor_label.setText(
            f'daemon: {state}（{"所有" if status.get("owned") else "attach"}）　session '
            f'{status.get("session")}　site {views.fmt(status.get("site_id"))}　caps_version '
            f'{views.fmt(status.get("caps_version"))}　USB attached {views.fmt(usb.get("attached"))}'
            f'　authority {views.fmt(authority.get("attached"))}' +
            (f'\n理由: {status["reason"]}' if status.get('reason') else ''))
        history = status.get('history') or []
        if history and (not self.log.toPlainText().endswith(history[-1])):
            self.log.appendPlainText(history[-1])
        if state == 'ready' and status.get('session') != self.ready_session:
            self.ready_session = status.get('session')
            self.site_ready.emit(status['socket'])
        if state != 'ready':
            self.confirm.setChecked(False)
        self._refresh_buttons()

    # --- boards / provision -------------------------------------------------------

    def import_boards(self):
        """Copy the probed identities and assignments from the boards screen."""
        rows = []
        for row in self.boards_view.rows:
            identity = row.identity
            role = 'bridge' if row.role == 'bridge_node' else 'bench' if row.role else None
            rows.append({'board': row.port, 'chip': identity.chip if identity else None,
                         'base_mac': identity.base_mac if identity else None, 'role': role,
                         'node_id': row.node_id})
        self.board_rows = rows
        self.jobs = []
        self.confirm.setChecked(False)
        self._render_boards()

    def set_board(self, board, role, node_id):
        for row in self.board_rows:
            if row['board'] == board:
                row['role'], row['node_id'] = role, node_id
        self.jobs = []
        self.confirm.setChecked(False)
        self._render_boards()

    def validate_plan(self):
        jobs, errors = plan_jobs(self.board_rows)
        self.jobs = jobs
        self.plan_label.setText('計画: ' + ('問題なし' if not errors else
                                            '／'.join(f'{b}: {"、".join(r)}' for b, r in errors.items())))
        self._render_boards()
        return errors

    def run_provision(self):
        if not self._can_run():
            return
        self.provision_serial += 1
        self.provisioning = True
        # The worker gets its own copies; results come back as new copies.
        self.provision.emit(self.provision_serial, deepcopy(self.jobs))
        self.confirm.setChecked(False)
        self._refresh_buttons()

    def _cancel(self):
        self.prov_worker.cancel(self.provision_serial)

    def _on_job(self, serial, job):
        if serial != self.provision_serial:
            return
        self.jobs = [job if old.board == job.board else old for old in self.jobs]
        self._render_boards()

    def _on_provision_finished(self, serial):
        if serial == self.provision_serial:
            self.provisioning = False
            self._refresh_buttons()

    def _can_run(self):
        planned = bool(self.jobs) and all(job.steps.get('plan') == 'done' for job in self.jobs)
        return (self.mode == 'LIVE' and planned and self.confirm.isChecked() and not self.provisioning
                and not self.stopping)

    def _refresh_buttons(self):
        self.run_button.setEnabled(self._can_run())
        self.cancel_button.setEnabled(self.provisioning)
        self.plan_button.setEnabled(self.mode == 'LIVE' and not self.provisioning)
        state = self.supervisor_status.get('state')
        busy = state in ('starting', 'attaching', 'ready', 'reconnecting', 'stopping')
        self.start_button.setEnabled(self.mode == 'LIVE' and not busy and not self.stopping)
        self.attach_button.setEnabled(self.mode == 'LIVE' and not busy and not self.stopping)
        self.stop_button.setEnabled(busy)

    def _render_boards(self):
        jobs = {job.board: job for job in self.jobs}
        self.board_table.setRowCount(len(self.board_rows))
        for r, row in enumerate(self.board_rows):
            job = jobs.get(row['board'])
            steps = ' '.join(f'{name}{STEP_MARKS.get(job.steps.get(name), "·")}'
                             for name in STEP_NAMES) if job else ''
            status = job_status_text(job) if job else '未計画'
            if job is not None and job.steps.get('plan') == 'failed':
                status += f'：{job.details.get("plan")}'
            texts = [row['board'], views.fmt(row['chip']),
                     '..' + row['base_mac'][-5:] if row['base_mac'] else '不明',
                     views.fmt(row['role'], none='未割当て'), views.fmt(row['node_id'], none='未割当て'),
                     status, steps]
            for c, text in enumerate(texts):
                if c == 3 and self.board_table.cellWidget(r, c) is None:
                    box = QComboBox()
                    box.addItems(['未割当て', *LAB_ROLES])
                    box.setCurrentText(row['role'] or '未割当て')
                    box.currentTextChanged.connect(
                        lambda value, board=row['board']: self._edit(board, role=value))
                    self.board_table.setCellWidget(r, c, box)
                    continue
                if c == 3:
                    continue
                cell = self.board_table.item(r, c)
                if cell is None:
                    cell = QTableWidgetItem()
                    self.board_table.setItem(r, c, cell)
                if cell.text() != text:
                    cell.setText(text)
        self._refresh_buttons()

    def _edit(self, board, *, role=None):
        for row in self.board_rows:
            if row['board'] == board:
                row['role'] = role if role in LAB_ROLES else None
        self.jobs = []
        self.confirm.setChecked(False)
        self._render_boards()

    # --- shutdown ----------------------------------------------------------------

    def shutdown(self):
        """Stop the owned daemon (attached ones are only detached) off the GUI thread."""
        if self.stopping or self.stopped:
            return
        self.stopping = True
        self.prov_worker.cancel(self.provision_serial)
        self.stop_requested.emit()
        self.provision_stop.emit()
        self._refresh_buttons()

    def _on_thread_finished(self):
        # No wait in the GUI thread: each worker thread reports its own end.
        self.threads_running -= 1
        if self.threads_running == 0:
            self.stopped = True
            self.shutdown_finished.emit()
